from typing import Any, Dict, List, Optional
from .models import Finding
from .checks.bola import BOLACheck
from .checks.mass_assignment import MassAssignmentCheck
from .checks.bfla import BFLACheck
from .checks.jwt_flaws import JWTFlawsCheck, Prober
from .checks.rate_limiting import RateLimitingCheck


class SecurityTestRunner:
    def __init__(self):
        self.bola = BOLACheck()
        self.mass_assignment = MassAssignmentCheck()
        self.bfla = BFLACheck()

    def run_static(self, results: List[Dict], endpoints: List[Dict]) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self.bola.run(results))
        findings.extend(self.mass_assignment.run(results, endpoints))
        findings.extend(self.bfla.run(results, endpoints))
        return findings

    async def run_active(
        self,
        prober: Prober,
        endpoints: List[Dict],
        sample_valid_token: str,
        jwt_protected_endpoint: str = "/api/orders",
        login_payload: Optional[dict] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []

        jwt_check = JWTFlawsCheck(protected_endpoint=jwt_protected_endpoint)
        findings.extend(await jwt_check.run(prober, sample_valid_token))

        rate_check = RateLimitingCheck()
        findings.extend(await rate_check.run(prober, endpoints, login_payload))

        return findings

    @staticmethod
    def summary(findings: List[Finding]) -> Dict[str, Any]:
        by_severity: Dict[str, int] = {}
        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        return {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "highest_score": max((f.score for f in findings), default=0.0),
        }
