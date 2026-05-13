"""Risk score aggregation from findings."""

from app.rules.base import RuleFinding

_SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 25.0,
    "high": 15.0,
    "medium": 8.0,
    "low": 3.0,
    "info": 1.0,
}


def compute_risk_score(findings: list[RuleFinding], cap: float = 100.0) -> float:
    """Sum weighted severities and cap at `cap`."""
    total = sum(_SEVERITY_WEIGHT.get(f.severity.lower(), 5.0) for f in findings)
    return float(min(total, cap))
