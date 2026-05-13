from app.rules.base import RuleFinding
from app.scoring import compute_risk_score


def test_risk_score_empty():
    assert compute_risk_score([]) == 0.0


def test_risk_score_caps():
    findings = [RuleFinding("x", "critical", "a")] * 10
    assert compute_risk_score(findings) == 100.0


def test_risk_score_weights():
    f = [
        RuleFinding("a", "high", "m1"),
        RuleFinding("b", "medium", "m2"),
    ]
    assert compute_risk_score(f) == 23.0
