"""
Finding is the only shared model in this package. Checks operate directly
on the list[dict] shape engine.run_scan() already produces — no wrapper
dataclass for scan results, to avoid a conversion layer that adds nothing.
"""
from dataclasses import dataclass, field
from .cvss import CVSSVector, base_score, severity_label


@dataclass
class Finding:
    check_id: str
    title: str
    endpoint: str
    method: str
    auth_context: str
    description: str
    evidence: str
    remediation: str
    vector: CVSSVector
    score: float = field(init=False)
    severity: str = field(init=False)

    def __post_init__(self):
        self.score = base_score(self.vector)
        self.severity = severity_label(self.score)

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "endpoint": self.endpoint,
            "method": self.method,
            "auth_context": self.auth_context,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cvss_vector": self.vector.to_string(),
            "cvss_score": self.score,
            "severity": self.severity,
        }
