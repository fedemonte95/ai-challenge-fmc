"""Registered rules listing."""

from fastapi import APIRouter

from app.schemas import RuleInfo

# Import side effects: register concrete rules
from app.rules import aws_iam  # noqa: F401
from app.rules import aws_network  # noqa: F401
from app.rules import aws_s3  # noqa: F401
from app.rules import azure_network  # noqa: F401
from app.rules import azure_storage  # noqa: F401
from app.rules.base import rule_registry

router = APIRouter()


@router.get("", response_model=list[RuleInfo])
def list_rules() -> list[RuleInfo]:
    return [
        RuleInfo(rule_id=cls.rule_id, title=cls.title, provider=cls.provider)
        for cls in rule_registry()
    ]
