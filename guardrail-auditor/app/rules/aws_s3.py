"""AWS S3-related rules: public ACLs and disabled public access blocks."""

from __future__ import annotations

from typing import Any

from app.iac_nav import as_bool, cfn_resources, hcl_unwrap, iter_terraform_resources
from app.rules.base import Rule, RuleFinding, register_rule

_PUBLIC_ACLS = frozenset({"public-read", "public-read-write"})


@register_rule
class AwsS3PublicAccess(Rule):
    rule_id = "aws.s3.public_access"
    title = "S3 bucket should block public access and avoid public ACLs"
    provider = "aws"

    def evaluate(self, parsed: dict[str, Any], source_kind: str) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        if source_kind == "terraform":
            findings.extend(self._terraform(parsed))
        elif source_kind == "cloudformation":
            findings.extend(self._cloudformation(parsed))
        return findings

    def _terraform(self, parsed: dict[str, Any]) -> list[RuleFinding]:
        out: list[RuleFinding] = []
        for rtype, name, attrs in iter_terraform_resources(parsed):
            if rtype == "aws_s3_bucket":
                acl = hcl_unwrap(attrs.get("acl"))
                if isinstance(acl, str) and acl.lower() in _PUBLIC_ACLS:
                    out.append(
                        RuleFinding(
                            rule_id=self.rule_id,
                            severity="high",
                            message=f"S3 bucket '{name}' uses a public ACL ({acl}).",
                            resource_path=f"resource.aws_s3_bucket.{name}",
                        )
                    )
            if rtype == "aws_s3_bucket_public_access_block":
                for flag, label in (
                    ("block_public_acls", "block_public_acls"),
                    ("block_public_policy", "block_public_policy"),
                    ("ignore_public_acls", "ignore_public_acls"),
                    ("restrict_public_buckets", "restrict_public_buckets"),
                ):
                    raw = attrs.get(flag)
                    b = as_bool(hcl_unwrap(raw)) if raw is not None else None
                    if b is False:
                        out.append(
                            RuleFinding(
                                rule_id=self.rule_id,
                                severity="high",
                                message=f"S3 public access block '{name}' disables {label}.",
                                resource_path=f"resource.aws_s3_bucket_public_access_block.{name}",
                            )
                        )
        return out

    def _cloudformation(self, template: dict[str, Any]) -> list[RuleFinding]:
        out: list[RuleFinding] = []
        for logical_id, rtype, props in cfn_resources(template):
            if rtype != "AWS::S3::Bucket":
                continue
            ac = props.get("AccessControl")
            if isinstance(ac, str) and ac in ("PublicRead", "PublicReadWrite"):
                out.append(
                    RuleFinding(
                        rule_id=self.rule_id,
                        severity="high",
                        message=f"S3 bucket '{logical_id}' sets AccessControl to {ac}.",
                        resource_path=f"Resources.{logical_id}.Properties.AccessControl",
                    )
                )
            pab = props.get("PublicAccessBlockConfiguration") or {}
            if isinstance(pab, dict):
                for key, label in (
                    ("BlockPublicAcls", "BlockPublicAcls"),
                    ("BlockPublicPolicy", "BlockPublicPolicy"),
                    ("IgnorePublicAcls", "IgnorePublicAcls"),
                    ("RestrictPublicBuckets", "RestrictPublicBuckets"),
                ):
                    if pab.get(key) is False:
                        out.append(
                            RuleFinding(
                                rule_id=self.rule_id,
                                severity="high",
                                message=f"S3 bucket '{logical_id}' disables {label} in PublicAccessBlockConfiguration.",
                                resource_path=f"Resources.{logical_id}.Properties.PublicAccessBlockConfiguration",
                            )
                        )
        return out
