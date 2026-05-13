"""Pydantic schemas for API I/O."""

from datetime import datetime

from pydantic import BaseModel, Field


class ScanCreate(BaseModel):
    source_name: str = Field(..., max_length=512)
    source_kind: str = Field(..., pattern="^(terraform|cloudformation)$")
    content: str = Field(..., description="Raw IaC text")


class FindingOut(BaseModel):
    id: int
    rule_id: str
    severity: str
    message: str
    resource_path: str | None = None

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    id: int
    source_name: str
    source_kind: str
    risk_score: float
    created_at: datetime
    findings: list[FindingOut] = []

    model_config = {"from_attributes": True}


class ScanSummary(BaseModel):
    id: int
    source_name: str
    source_kind: str
    risk_score: float
    created_at: datetime
    finding_count: int

    model_config = {"from_attributes": True}


class RuleInfo(BaseModel):
    rule_id: str
    title: str
    provider: str
