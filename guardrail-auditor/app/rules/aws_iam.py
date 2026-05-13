"""AWS IAM rules: dangerously broad policy documents."""

from __future__ import annotations

from typing import Any

from app.iac_nav import iter_terraform_resources, parse_policy_document
from app.rules.base import Rule, RuleFinding, register_rule

_WILDCARD_ACTION = "*"
_WILDCARD_RESOURCE = "*"


def _statements(doc: dict[str, Any]) -> list[dict[str, Any]]:
    stmt = doc.get("Statement")
    if stmt is None:
        return []
    if isinstance(stmt, dict):
        return [stmt]
    if isinstance(stmt, list):
        return [s for s in stmt if isinstance(s, dict)]
    return []


def _actions_include_wildcard(st: dict[str, Any]) -> bool:
    act = st.get("Action")
    if act == _WILDCARD_ACTION:
        return True
    if isinstance(act, list) and _WILDCARD_ACTION in act:
        return True
    return False


def _resources_include_wildcard(st: dict[str, Any]) -> bool:
    res = st.get("Resource")
    if res == _WILDCARD_RESOURCE:
        return True
    if isinstance(res, list) and _WILDCARD_RESOURCE in res:
        return True
    return False


def _effect_allows(st: dict[str, Any]) -> bool:
    eff = st.get("Effect")
    return eff == "Allow"


@register_rule
class AwsIamWildcardAdmin(Rule):
    rule_id = "aws.iam.wildcard_admin"
    title = "IAM inline policies should not combine Action * with Resource *"
    provider = "aws"

    def evaluate(self, parsed: dict[str, Any], source_kind: str) -> list[RuleFinding]:
        if source_kind != "terraform":
            return []
        return self._terraform(parsed)

    def _terraform(self, parsed: dict[str, Any]) -> list[RuleFinding]:
        out: list[RuleFinding] = []
        policy_resource_types = (
            "aws_iam_role_policy",
            "aws_iam_user_policy",
            "aws_iam_group_policy",
        )
        for rtype, name, attrs in iter_terraform_resources(parsed):
            if rtype not in policy_resource_types:
                continue
            doc = parse_policy_document(attrs.get("policy"))
            if not doc:
                continue
            for st in _statements(doc):
                if not _effect_allows(st):
                    continue
                if _actions_include_wildcard(st) and _resources_include_wildcard(st):
                    out.append(
                        RuleFinding(
                            rule_id=self.rule_id,
                            severity="critical",
                            message=(
                                f"IAM inline policy '{name}' contains an Allow statement with Action * "
                                "and Resource *."
                            ),
                            resource_path=f"resource.{rtype}.{name}",
                        )
                    )
                    break
        return out
