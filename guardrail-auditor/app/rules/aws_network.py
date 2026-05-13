"""AWS network rules: overly permissive security group ingress."""

from __future__ import annotations

from typing import Any

from app.iac_nav import cfn_resources, hcl_unwrap, iter_terraform_resources
from app.rules.base import Rule, RuleFinding, register_rule

_SENSITIVE_PORTS = {22, 3389, 3306, 5432, 6379, 27017}


def _port_in_range(from_p: int | None, to_p: int | None, target: int) -> bool:
    if from_p is None or to_p is None:
        return False
    if from_p == 0 and to_p == 0:
        return True
    return from_p <= target <= to_p


def _parse_port(val: Any) -> int | None:
    u = hcl_unwrap(val)
    if u is None:
        return None
    if isinstance(u, bool):
        return None
    if isinstance(u, int):
        return u
    if isinstance(u, str):
        if u == "*":
            return None
        try:
            return int(u)
        except ValueError:
            return None
    return None


def _collect_cidr_strings(val: Any) -> list[str]:
    if val is None:
        return []
    u = hcl_unwrap(val)
    if isinstance(u, str):
        return [u]
    if isinstance(u, list):
        acc: list[str] = []
        for item in u:
            acc.extend(_collect_cidr_strings(item))
        return acc
    return []


def _is_world_open(cidrs: list[str]) -> bool:
    for c in cidrs:
        if c in ("0.0.0.0/0", "::/0"):
            return True
    return False


@register_rule
class AwsSecurityGroupWideOpen(Rule):
    rule_id = "aws.network.sg_ingress_0_0_0_0"
    title = "Security group ingress should not expose sensitive ports to the internet"
    provider = "aws"

    def evaluate(self, parsed: dict[str, Any], source_kind: str) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        if source_kind == "terraform":
            findings.extend(self._terraform(parsed))
        elif source_kind == "cloudformation":
            findings.extend(self._cloudformation(parsed))
        return findings

    def _check_ingress_block(
        self,
        block: dict[str, Any],
        resource_label: str,
    ) -> list[RuleFinding]:
        out: list[RuleFinding] = []
        cidrs = _collect_cidr_strings(block.get("cidr_blocks"))
        cidrs.extend(_collect_cidr_strings(block.get("ipv6_cidr_blocks")))
        if not _is_world_open(cidrs):
            return out
        from_p = _parse_port(block.get("from_port"))
        to_p = _parse_port(block.get("to_port"))
        for port in _SENSITIVE_PORTS:
            if _port_in_range(from_p, to_p, port):
                out.append(
                    RuleFinding(
                        rule_id=self.rule_id,
                        severity="critical",
                        message=(
                            f"Security group '{resource_label}' allows internet-wide ingress "
                            f"({cidrs}) including port {port}."
                        ),
                        resource_path=resource_label,
                    )
                )
                break
        return out

    def _terraform(self, parsed: dict[str, Any]) -> list[RuleFinding]:
        out: list[RuleFinding] = []
        for rtype, name, attrs in iter_terraform_resources(parsed):
            if rtype == "aws_security_group":
                ingress = attrs.get("ingress")
                blocks = ingress if isinstance(ingress, list) else []
                for idx, block in enumerate(blocks):
                    if isinstance(block, dict):
                        label = f"resource.aws_security_group.{name}.ingress[{idx}]"
                        out.extend(self._check_ingress_block(block, label))
            if rtype == "aws_security_group_rule":
                if hcl_unwrap(attrs.get("type")) != "ingress":
                    continue
                label = f"resource.aws_security_group_rule.{name}"
                out.extend(self._check_ingress_block(attrs, label))
        return out

    def _cloudformation(self, template: dict[str, Any]) -> list[RuleFinding]:
        out: list[RuleFinding] = []
        for logical_id, rtype, props in cfn_resources(template):
            if rtype != "AWS::EC2::SecurityGroup":
                continue
            ingress = props.get("SecurityGroupIngress") or []
            if not isinstance(ingress, list):
                continue
            for idx, rule in enumerate(ingress):
                if not isinstance(rule, dict):
                    continue
                cidrs: list[str] = []
                for key in ("CidrIp", "CidrIpv6"):
                    v = rule.get(key)
                    if isinstance(v, str):
                        cidrs.append(v)
                src = rule.get("SourceSecurityGroupId")
                if isinstance(src, str) and src in ("0.0.0.0/0", "::/0"):
                    cidrs.append(src)
                if not _is_world_open(cidrs):
                    continue
                from_p = _parse_port(rule.get("FromPort"))
                to_p = _parse_port(rule.get("ToPort"))
                for port in _SENSITIVE_PORTS:
                    if _port_in_range(from_p, to_p, port):
                        out.append(
                            RuleFinding(
                                rule_id=self.rule_id,
                                severity="critical",
                                message=(
                                    f"Security group '{logical_id}' allows internet-wide ingress on port {port} "
                                    f"(rule index {idx})."
                                ),
                                resource_path=f"Resources.{logical_id}.Properties.SecurityGroupIngress[{idx}]",
                            )
                        )
                        break
        return out
