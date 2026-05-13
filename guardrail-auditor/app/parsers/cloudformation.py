"""CloudFormation template parsing (YAML/JSON)."""

from pathlib import Path
from typing import Any

import yaml


def parse_cfn_string(content: str) -> dict[str, Any]:
    """Parse a CloudFormation template string (YAML or JSON)."""
    data = yaml.safe_load(content)
    if not isinstance(data, dict):
        msg = "CloudFormation template must deserialize to an object"
        raise ValueError(msg)
    return data


def parse_cfn_file(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as f:
        return parse_cfn_string(f.read())
