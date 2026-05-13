from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Base
from app.scan_service import create_scan_with_analysis, evaluate_all_rules, parse_payload
from app.schemas import ScanCreate

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_insecure_aws_tf_flags_high_risk_patterns():
    content = _load("insecure_aws.tf")
    parsed = parse_payload("terraform", content)
    findings = evaluate_all_rules(parsed, "terraform")
    rule_ids = {f.rule_id for f in findings}
    assert "aws.s3.public_access" in rule_ids
    assert "aws.network.sg_ingress_0_0_0_0" in rule_ids
    assert "aws.iam.wildcard_admin" in rule_ids


def test_secure_aws_tf_minimal_findings():
    content = _load("secure_aws.tf")
    parsed = parse_payload("terraform", content)
    findings = evaluate_all_rules(parsed, "terraform")
    assert findings == []


def test_insecure_cfn_yaml():
    content = _load("insecure.cfn.yaml")
    parsed = parse_payload("cloudformation", content)
    findings = evaluate_all_rules(parsed, "cloudformation")
    rule_ids = {f.rule_id for f in findings}
    assert "aws.s3.public_access" in rule_ids
    assert "aws.network.sg_ingress_0_0_0_0" in rule_ids


def test_insecure_azure_tf():
    content = _load("insecure_azure.tf")
    parsed = parse_payload("terraform", content)
    findings = evaluate_all_rules(parsed, "terraform")
    rule_ids = {f.rule_id for f in findings}
    assert "azure.storage.https_only" in rule_ids
    assert "azure.network.nsg_open_inbound" in rule_ids


def test_create_scan_wraps_parser_errors():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    db = session_factory()
    payload = ScanCreate(
        source_name="bad",
        source_kind="terraform",
        content="this is not hcl {{{{",
    )
    with pytest.raises(ValueError, match="Failed to parse"):
        create_scan_with_analysis(db, payload)
