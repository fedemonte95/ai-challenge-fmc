"""Azure Storage rules: HTTPS-only traffic."""

from __future__ import annotations

from typing import Any

from app.iac_nav import as_bool, hcl_unwrap, iter_terraform_resources
from app.rules.base import Rule, RuleFinding, register_rule


@register_rule
class AzureStorageHttpsOnly(Rule):
    rule_id = "azure.storage.https_only"
    title = "Storage accounts should enforce HTTPS-only traffic"
    provider = "azure"

    def evaluate(self, parsed: dict[str, Any], source_kind: str) -> list[RuleFinding]:
        if source_kind != "terraform":
            return []
        return self._terraform(parsed)

    def _terraform(self, parsed: dict[str, Any]) -> list[RuleFinding]:
        out: list[RuleFinding] = []
        for rtype, name, attrs in iter_terraform_resources(parsed):
            if rtype != "azurerm_storage_account":
                continue
            https_only = attrs.get("enable_https_traffic_only")
            b = as_bool(hcl_unwrap(https_only)) if https_only is not None else None
            if b is False:
                out.append(
                    RuleFinding(
                        rule_id=self.rule_id,
                        severity="high",
                        message=f"Storage account '{name}' has enable_https_traffic_only = false.",
                        resource_path=f"resource.azurerm_storage_account.{name}",
                    )
                )
        return out
