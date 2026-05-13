"""Abstract rule base and registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, ClassVar


@dataclass
class RuleFinding:
    rule_id: str
    severity: str  # critical, high, medium, low, info
    message: str
    resource_path: str | None = None


class Rule(ABC):
    """Single guardrail check against parsed IaC."""

    rule_id: ClassVar[str]
    title: ClassVar[str]
    provider: ClassVar[str]  # aws, azure, gcp, ...

    @abstractmethod
    def evaluate(self, parsed: dict[str, Any], source_kind: str) -> list[RuleFinding]:
        """Return zero or more findings for the given document."""


_rule_classes: list[type[Rule]] = []


def register_rule(cls: type[Rule]) -> type[Rule]:
    _rule_classes.append(cls)
    return cls


def rule_registry() -> list[type[Rule]]:
    return list(_rule_classes)
