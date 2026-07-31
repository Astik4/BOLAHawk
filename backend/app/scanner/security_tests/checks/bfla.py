from typing import List, Dict
from ..models import Finding
from ..cvss import CVSSVector, AV, AC, PR, UI, SCOPE, IMPACT


class BFLACheck:
    check_id = "BFLA"

    def run(self, results: List[Dict], endpoints: List[Dict], admin_context: str = "admin_user") -> List[Finding]:
        findings = []
        admin_keys = {
            (ep["path"], ep["method"])
            for ep in endpoints
            if ep.get("admin_only")
        }

        for r in results:
            if (r["endpoint"], r["method"]) not in admin_keys:
                continue
            if r["auth_context"] in ("anonymous", admin_context):
                continue
            if r["status_code"] == 200:
                findings.append(Finding(
                    check_id=self.check_id,
                    title=f"BFLA on {r['method']} {r['endpoint']}",
                    endpoint=r["endpoint"],
                    method=r["method"],
                    auth_context=r["auth_context"],
                    description=(
                        f"'{r['auth_context']}' (non-admin) successfully called an admin-only "
                        f"function. Only the JWT was checked — not role/is_admin."
                    ),
                    evidence=f"status={r['status_code']}",
                    remediation="Add a role check (current_user.is_admin) inside the route, not just @token_required.",
                    vector=CVSSVector(
                        av=AV.NETWORK, ac=AC.LOW, pr=PR.LOW, ui=UI.NONE,
                        scope=SCOPE.CHANGED,
                        conf=IMPACT.HIGH, integ=IMPACT.NONE, avail=IMPACT.NONE,
                    ),
                ))
        return findings
