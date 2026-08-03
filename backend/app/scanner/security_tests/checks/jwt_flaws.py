"""
Active check — crafts tokens itself and fires requests via `prober`,
which security_orchestrator.py wires to request_runner.send_request.

Prober signature: async def prober(path, method, headers, json_data=None) -> (status_code, body)
"""
import jwt as pyjwt
from typing import Awaitable, Callable, List, Optional, Tuple, Any
from ..models import Finding
from ..cvss import CVSSVector, AV, AC, PR, UI, SCOPE, IMPACT

Prober = Callable[[str, str, dict, Optional[dict]], Awaitable[Tuple[int, Any]]]

# Small, well-known weak-secret list (same ones jwt_tool/jwt_cracker ship with)
# — used only against this project's own vulnerable-target-api.
_COMMON_WEAK_SECRETS = ["secret", "changeme", "password", "123456", "key"]


class JWTFlawsCheck:
    check_id = "JWT-FLAWS"

    def __init__(self, protected_endpoint: str = "/api/orders", method: str = "GET"):
        self.protected_endpoint = protected_endpoint
        self.method = method

    async def run(self, prober: Prober, sample_valid_token: str) -> List[Finding]:
        findings = []
        findings += await self._check_alg_none(prober, sample_valid_token)
        findings += await self._check_weak_secret(prober, sample_valid_token)
        findings += self._check_missing_expiry(sample_valid_token)
        return findings

    async def _check_alg_none(self, prober: Prober, sample_valid_token: str) -> List[Finding]:
        # nosemgrep: python.jwt.security.unverified-jwt-decode.unverified-jwt-decode
        # Intentional: we strip the signature to extract claims for the alg:none forgery attack.
        claims = pyjwt.decode(sample_valid_token, options={"verify_signature": False})  # nosemgrep
        # nosemgrep: python.jwt.security.jwt-none-alg.jwt-python-none-alg
        # Intentional: this IS the forged token we fire at the target to test whether it accepts alg=none.
        forged = pyjwt.encode(claims, key="", algorithm="none")  # nosemgrep
        status, _ = await prober(self.protected_endpoint, self.method, {"Authorization": f"Bearer {forged}"})
        if status == 200:
            return [Finding(
                check_id=self.check_id,
                title="JWT alg:none accepted",
                endpoint=self.protected_endpoint,
                method=self.method,
                auth_context="forged",
                description="token_required accepts a token with header alg='none', bypassing signature verification entirely.",
                evidence=f"status={status}",
                remediation="Decode with an explicit algorithms allow-list (jwt.decode(token, get_jwt_secret(), algorithms=['HS256'])) — never branch on the token's own alg header.",
                vector=CVSSVector(av=AV.NETWORK, ac=AC.LOW, pr=PR.NONE, ui=UI.NONE,
                                   scope=SCOPE.CHANGED, conf=IMPACT.HIGH, integ=IMPACT.HIGH, avail=IMPACT.HIGH),
            )]
        return []

    async def _check_weak_secret(self, prober: Prober, sample_valid_token: str) -> List[Finding]:
        # nosemgrep: python.jwt.security.unverified-jwt-decode.unverified-jwt-decode
        # Intentional: decoding without verification to extract claims before re-signing with a weak secret.
        claims = pyjwt.decode(sample_valid_token, options={"verify_signature": False})  # nosemgrep
        for secret in _COMMON_WEAK_SECRETS:
            forged = pyjwt.encode(claims, key=secret, algorithm="HS256")
            status, _ = await prober(self.protected_endpoint, self.method, {"Authorization": f"Bearer {forged}"})
            if status == 200:
                return [Finding(
                    check_id=self.check_id,
                    title="JWT signed with a weak/guessable secret",
                    endpoint=self.protected_endpoint,
                    method=self.method,
                    auth_context="forged",
                    description="A token re-signed with a common weak secret was accepted, confirming JWT_SECRET is brute-forceable.",
                    evidence="secret=<redacted, matched common wordlist entry>",
                    remediation="Use a high-entropy, randomly generated signing secret (32+ bytes) loaded from environment config, not a hardcoded string.",
                    vector=CVSSVector(av=AV.NETWORK, ac=AC.LOW, pr=PR.NONE, ui=UI.NONE,
                                       scope=SCOPE.CHANGED, conf=IMPACT.HIGH, integ=IMPACT.HIGH, avail=IMPACT.HIGH),
                )]
        return []

    def _check_missing_expiry(self, sample_valid_token: str) -> List[Finding]:
        """A token with no `exp` claim never stops being valid, so a single
        leaked token is a permanent credential. This one is a claims
        inspection rather than a probe — there's nothing to fire at the
        server, the evidence is in the token the server already issued."""
        # nosemgrep: python.jwt.security.unverified-jwt-decode.unverified-jwt-decode
        # Intentional: inspecting claims of a token we were legitimately issued.
        claims = pyjwt.decode(sample_valid_token, options={"verify_signature": False})  # nosemgrep
        if "exp" in claims:
            return []
        return [Finding(
            check_id=self.check_id,
            title="JWT issued without an expiry claim",
            endpoint="/api/auth/login",
            method="POST",
            auth_context="alice_user",
            description="Tokens returned by the login endpoint carry no 'exp' claim, so they stay valid indefinitely. A token captured once is a permanent credential, and there is no way to age out a session.",
            evidence=f"claims={sorted(claims.keys())} (no 'exp')",
            remediation="Set a short 'exp' on every issued token and verify it on decode; pair it with a refresh token if longer sessions are needed.",
            vector=CVSSVector(av=AV.NETWORK, ac=AC.HIGH, pr=PR.NONE, ui=UI.NONE,
                               scope=SCOPE.UNCHANGED, conf=IMPACT.HIGH, integ=IMPACT.LOW, avail=IMPACT.NONE),
        )]
