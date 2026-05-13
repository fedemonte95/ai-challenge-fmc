"""Azure network rules: NSG rules exposing admin ports to the internet."""

from __future__ import annotations

from typing import Any

from app.iac_nav import hcl_unwrap, iter_terraform_resources
from app.rules.base import Rule, RuleFinding, register_rule

_INTERNET_PREFIXES = frozenset({"*", "Internet", "0.0.0.0/0", "::/0", "Any"})
_RISKY_PORTS = frozenset({"22", "3389", "*"})


def _tf_str(val: Any) -> str | None:
    u = hcl_unwrap(val)
    if isinstance(u, str):
        return u
    if isinstance(u, (int, float)):
        return str(u)
    return None


def _collect_prefixes(attrs: dict[str, Any]) -> list[str]:
    out: list[str] = []
    single = _tf_str(attrs.get("source_address_prefix"))
    if single:
        out.append(single)
    raw = attrs.get("source_address_prefixes")
    if isinstance(raw, list):
        for item in raw:
            s = _tf_str(item)
            if s:
                out.append(s)
    return out


@register_rule
class AzureNsgOpenInbound(Rule):
    rule_id = "azure.network.nsg_open_inbound"
    title = "NSG rules should not expose SSH/RDP to the internet"
    provider = "azure"

    def evaluate(self, parsed: dict[str, Any], source_kind: str) -> list[RuleFinding]:
        if source_kind != "terraform":
            return []
        return self._terraform(parsed)

    def _terraform(self, parsed: dict[str, Any]) -> list[RuleFinding]:
        out: list[RuleFinding] = []
        for rtype, name, attrs in iter_terraform_resources(parsed):
            if rtype != "azurerm_network_security_rule":
                continue
            direction = (_tf_str(attrs.get("direction")) or "").lower()
            access = (_tf_str(attrs.get("access")) or "").lower()
            if direction != "inbound" or access != "allow":
                continue
            prefixes = _collect_prefixes(attrs)
            if not any(p in _INTERNET_PREFIXES for p in prefixes):
                continue
            ports: set[str] = set()
            if dp := _tf_str(attrs.get("destination_port_range")):
                ports.add(dp)
            raw_ranges = attrs.get("destination_port_ranges")
            if isinstance(raw_ranges, list):
                for item in raw_ranges:
                    if p := _tf_str(item):
                        ports.add(p)
            if ports & _RISKY_PORTS:
                out.append(
                    RuleFinding(
                        rule_id=self.rule_id,
                        severity="critical",
                        message=(
                            f"NSG rule '{name}' allows inbound access from the internet to "
                            f"ports {sorted(ports)}."
                        ),
                        resource_path=f"resource.azurerm_network_security_rule.{name}",
                    )
                )
        return out
