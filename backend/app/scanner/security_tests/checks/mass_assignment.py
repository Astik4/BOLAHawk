from typing import List, Dict
from ..models import Finding
from ..cvss import CVSSVector, AV, AC, PR, UI, SCOPE, IMPACT


def _get_nested(body: dict, dotted_path: str):
    node = body
    for part in dotted_path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


class MassAssignmentCheck:
    """
    Flags a privileged field (e.g. 'user.role') coming back set to a
    privileged value in a successful signup/registration response, when
    the request was sent under a non-privileged context.

    Endpoint config (endpoints.json) drives this via:
      "sensitive_fields": [["user.role", ["admin"]], ["user.is_admin", [true]]]
    """
    check_id = "MASS-ASSIGNMENT"

    def run(self, results: List[Dict], endpoints: List[Dict]) -> List[Finding]:
        findings = []
        meta_by_key = {
            (ep["path"], ep["method"]): ep
            for ep in endpoints
            if ep.get("sensitive_fields")
        }

        for r in results:
            key = (r["endpoint"], r["method"])
            meta = meta_by_key.get(key)
            if not meta or r["auth_context"] == "admin_user":
                continue
            if r["status_code"] not in (200, 201):
                continue

            body = r.get("response_body")
            if not isinstance(body, dict):
                continue

            for field_path, privileged_values in meta["sensitive_fields"]:
                value = _get_nested(body, field_path)
                if value is not None and value in privileged_values:
                    findings.append(Finding(
                        check_id=self.check_id,
                        title=f"Mass Assignment on {r['method']} {r['endpoint']}",
                        endpoint=r["endpoint"],
                        method=r["method"],
                        auth_context=r["auth_context"],
                        description=(
                            f"Field '{field_path}' was accepted from the request body and set to "
                            f"a privileged value ('{value}') for an unauthenticated signup."
                        ),
                        evidence=f"field={field_path} value={value} status={r['status_code']}",
                        remediation=(
                            "Build the User model from an explicit allow-listed schema "
                            "(e.g. only username/password) instead of User(**request_body)."
                        ),
                        vector=CVSSVector(
                            av=AV.NETWORK, ac=AC.LOW, pr=PR.NONE, ui=UI.NONE,
                            scope=SCOPE.CHANGED,
                            conf=IMPACT.LOW, integ=IMPACT.HIGH, avail=IMPACT.NONE,
                        ),
                    ))
        return findings
