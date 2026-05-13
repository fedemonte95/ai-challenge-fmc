"""Terraform / HCL parsing via python-hcl2."""

from io import StringIO
from pathlib import Path
from typing import Any

import hcl2


def parse_hcl_string(content: str) -> dict[str, Any]:
    """Parse HCL source into a dict structure."""
    return hcl2.load(StringIO(content))


def parse_hcl_file(path: str | Path) -> dict[str, Any]:
    """Parse a .tf file from disk."""
    with Path(path).open("r", encoding="utf-8") as f:
        return hcl2.load(f)
