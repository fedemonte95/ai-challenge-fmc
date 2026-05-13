"""Orchestrate parsing, rule evaluation, and persistence for scans."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app import models
from app.parsers import cloudformation as cfn_parser
from app.parsers import terraform as tf_parser
from app.rules import aws_iam  # noqa: F401
from app.rules import aws_network  # noqa: F401
from app.rules import aws_s3  # noqa: F401
from app.rules import azure_network  # noqa: F401
from app.rules import azure_storage  # noqa: F401
from app.rules.base import rule_registry
from app.schemas import ScanCreate
from app.scoring import compute_risk_score


def parse_payload(source_kind: str, content: str) -> dict[str, Any]:
    if source_kind == "terraform":
        return tf_parser.parse_hcl_string(content)
    if source_kind == "cloudformation":
        return cfn_parser.parse_cfn_string(content)
    msg = f"Unsupported source_kind: {source_kind}"
    raise ValueError(msg)


def evaluate_all_rules(parsed: dict[str, Any], source_kind: str) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    for cls in rule_registry():
        findings.extend(cls().evaluate(parsed, source_kind))
    return findings


def create_scan_with_analysis(db: Session, payload: ScanCreate) -> models.Scan:
    try:
        parsed = parse_payload(payload.source_kind, payload.content)
    except Exception as e:
        msg = f"Failed to parse IaC: {e}"
        raise ValueError(msg) from e
    rule_findings = evaluate_all_rules(parsed, payload.source_kind)
    score = compute_risk_score(rule_findings)

    scan = models.Scan(
        source_name=payload.source_name,
        source_kind=payload.source_kind,
        raw_payload=payload.content,
        risk_score=score,
    )
    db.add(scan)
    db.flush()

    for rf in rule_findings:
        db.add(
            models.Finding(
                scan_id=scan.id,
                rule_id=rf.rule_id,
                severity=rf.severity,
                message=rf.message,
                resource_path=rf.resource_path,
            )
        )
    db.commit()
    db.refresh(scan)
    return scan


def get_scan_with_findings(db: Session, scan_id: int) -> models.Scan | None:
    stmt = (
        select(models.Scan)
        .options(selectinload(models.Scan.findings))
        .where(models.Scan.id == scan_id)
    )
    return db.scalars(stmt).first()


def list_scans_with_findings(db: Session, limit: int = 100) -> list[models.Scan]:
    stmt = (
        select(models.Scan)
        .options(selectinload(models.Scan.findings))
        .order_by(models.Scan.created_at.desc())
        .limit(limit)
    )
    return list(db.scalars(stmt))
