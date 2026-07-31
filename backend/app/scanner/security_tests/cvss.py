"""
CVSS v3.1 Base Score calculator.

Implements the public CVSS v3.1 base metric formula (FIRST.org spec) so
findings get a real, reproducible score + vector string instead of a
hardcoded number. No target-specific logic lives here.
"""
from dataclasses import dataclass
from enum import Enum


class AV(str, Enum):
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class AC(str, Enum):
    LOW = "L"
    HIGH = "H"


class PR(str, Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class UI(str, Enum):
    NONE = "N"
    REQUIRED = "R"


class SCOPE(str, Enum):
    UNCHANGED = "U"
    CHANGED = "C"


class IMPACT(str, Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"


_AV_W = {AV.NETWORK: 0.85, AV.ADJACENT: 0.62, AV.LOCAL: 0.55, AV.PHYSICAL: 0.2}
_AC_W = {AC.LOW: 0.77, AC.HIGH: 0.44}
_UI_W = {UI.NONE: 0.85, UI.REQUIRED: 0.62}
_IMPACT_W = {IMPACT.NONE: 0.0, IMPACT.LOW: 0.22, IMPACT.HIGH: 0.56}

# PR weight depends on scope
_PR_W_UNCHANGED = {PR.NONE: 0.85, PR.LOW: 0.62, PR.HIGH: 0.27}
_PR_W_CHANGED = {PR.NONE: 0.85, PR.LOW: 0.68, PR.HIGH: 0.5}


@dataclass(frozen=True)
class CVSSVector:
    av: AV
    ac: AC
    pr: PR
    ui: UI
    scope: SCOPE
    conf: IMPACT
    integ: IMPACT
    avail: IMPACT

    def to_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.av.value}/AC:{self.ac.value}/PR:{self.pr.value}"
            f"/UI:{self.ui.value}/S:{self.scope.value}/C:{self.conf.value}"
            f"/I:{self.integ.value}/A:{self.avail.value}"
        )


def _round_up(value: float) -> float:
    """CVSS spec's roundup: round to nearest 0.1, always up."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (int_input // 10000 + 1) / 10


def base_score(v: CVSSVector) -> float:
    pr_table = _PR_W_CHANGED if v.scope == SCOPE.CHANGED else _PR_W_UNCHANGED
    iss = 1 - ((1 - _IMPACT_W[v.conf]) * (1 - _IMPACT_W[v.integ]) * (1 - _IMPACT_W[v.avail]))

    if v.scope == SCOPE.UNCHANGED:
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * _AV_W[v.av] * _AC_W[v.ac] * pr_table[v.pr] * _UI_W[v.ui]

    if impact <= 0:
        return 0.0

    if v.scope == SCOPE.UNCHANGED:
        score = min(impact + exploitability, 10.0)
    else:
        score = min(1.08 * (impact + exploitability), 10.0)

    return _round_up(score)


def severity_label(score: float) -> str:
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"
