from typing import List, Dict
from ..models import Finding
from ..cvss import CVSSVector, AV, AC, PR, UI, SCOPE, IMPACT


class BOLACheck:
    """
    Reads results tagged with `resource_owner_id` / `requested_id` — these
    only come from the cross-owner probes added in engine.py
    (see run_bola_cross_owner_probes), where auth_context X deliberately
    requests a resource owned by auth_context Y. A 200 there means the
    ownership check that should exist doesn't.

    Untagged results (the normal Phase 4 matrix, where everyone requests
    their own default order_id) are ignored — they can't prove or disprove
    BOLA either way.
    """
    check_id = "BOLA"

    def run(self, results: List[Dict]) -> List[Finding]:
        findings = []
        for r in results:
            owner = r.get("resource_owner_id")
            if not owner:
                continue
            if r["auth_context"] == owner:
                continue
            if r["status_code"] == 200:
                findings.append(Finding(
                    check_id=self.check_id,
                    title=f"BOLA on {r['method']} {r['endpoint']}",
                    endpoint=r["endpoint"],
                    method=r["method"],
                    auth_context=r["auth_context"],
                    description=(
                        f"'{r['auth_context']}' retrieved a resource (order {r.get('requested_id')}) "
                        f"owned by '{owner}' — no ownership check enforced."
                    ),
                    evidence=f"requested_id={r.get('requested_id')} status=200 owner={owner}",
                    remediation=(
                        "Check order.user_id == current_user.id (or equivalent ownership check) "
                        "before returning the resource, not just that the JWT is valid."
                    ),
                    vector=CVSSVector(
                        av=AV.NETWORK, ac=AC.LOW, pr=PR.LOW, ui=UI.NONE,
                        scope=SCOPE.UNCHANGED,
                        conf=IMPACT.HIGH, integ=IMPACT.NONE, avail=IMPACT.NONE,
                    ),
                ))
        return findings
