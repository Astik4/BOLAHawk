import asyncio
from typing import Awaitable, Callable, Dict, List, Optional, Tuple, Any
from ..models import Finding
from ..cvss import CVSSVector, AV, AC, PR, UI, SCOPE, IMPACT

Prober = Callable[[str, str, dict, Optional[dict]], Awaitable[Tuple[int, Any]]]


class RateLimitingCheck:
    check_id = "RATE-LIMITING"

    def __init__(self, attempts: int = 20):
        self.attempts = attempts

    async def run(
        self,
        prober: Prober,
        endpoints: List[Dict],
        payload: Optional[dict] = None,
    ) -> List[Finding]:
        findings = []
        for ep in endpoints:
            if not ep.get("rate_limit_expected"):
                continue

            responses = await asyncio.gather(*[
                prober(ep["path"], ep["method"], {}, payload) for _ in range(self.attempts)
            ])
            codes = [status for status, _ in responses]

            if 429 not in codes:
                findings.append(Finding(
                    check_id=self.check_id,
                    title=f"Missing rate limiting on {ep['method']} {ep['path']}",
                    endpoint=ep["path"],
                    method=ep["method"],
                    auth_context="anonymous",
                    description=(
                        f"{self.attempts} rapid requests all returned non-429 statuses "
                        "— no throttling on repeated login attempts."
                    ),
                    evidence=f"status_codes={codes}",
                    remediation="Add per-IP/per-account rate limiting (e.g. Flask-Limiter) to POST /api/auth/login.",
                    vector=CVSSVector(
                        av=AV.NETWORK, ac=AC.LOW, pr=PR.NONE, ui=UI.NONE,
                        scope=SCOPE.UNCHANGED,
                        conf=IMPACT.NONE, integ=IMPACT.NONE, avail=IMPACT.LOW,
                    ),
                ))
        return findings
