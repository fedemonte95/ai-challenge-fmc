"""Shared helpers to walk Terraform (hcl2) and CloudFormation structures."""

from __future__ import annotations

import json
from typing import Any, Iterator


def hcl_unwrap(value: Any) -> Any:
    """Flatten single-element lists and strip redundant HCL quote layers from strings."""
    if isinstance(value, list) and len(value) == 1:
        return hcl_unwrap(value[0])
    if isinstance(value, str):
        s = value
        while len(s) >= 2 and s[0] == '"' and s[-1] == '"':
            s = s[1:-1]
        return s
    return value


def iter_terraform_resources(parsed: dict[str, Any]) -> Iterator[tuple[str, str, dict[str, Any]]]:
    """Yield (resource_type, resource_name, attributes_dict).

    Supports modern python-hcl2 nested dict output as well as older list-based shapes.
    """
    for block in parsed.get("resource", []) or []:
        if not isinstance(block, dict):
            continue
        for rtype_key, instances in block.items():
            rtype = rtype_key.strip('"') if isinstance(rtype_key, str) else str(rtype_key)

            if isinstance(instances, dict):
                for name_key, body in instances.items():
                    if not isinstance(body, dict):
                        continue
                    name = name_key.strip('"') if isinstance(name_key, str) else str(name_key)
                    yield rtype, name, body
                continue

            if isinstance(instances, list):
                for inst in instances:
                    if not isinstance(inst, dict):
                        continue
                    for name, body_list in inst.items():
                        nm = name.strip('"') if isinstance(name, str) else str(name)
                        if not isinstance(body_list, list) or not body_list:
                            continue
                        body = body_list[0] if isinstance(body_list[0], dict) else {}
                        if isinstance(body, dict):
                            yield rtype, nm, body


def cfn_resources(template: dict[str, Any]) -> Iterator[tuple[str, str, dict[str, Any]]]:
    """Yield (logical_id, resource_type, properties)."""
    resources = template.get("Resources") or {}
    if not isinstance(resources, dict):
        return
    for logical_id, spec in resources.items():
        if not isinstance(spec, dict):
            continue
        rtype = spec.get("Type")
        props = spec.get("Properties") or {}
        if isinstance(rtype, str) and isinstance(props, dict):
            yield str(logical_id), rtype, props


def as_bool(value: Any) -> bool | None:
    u = hcl_unwrap(value)
    if isinstance(u, bool):
        return u
    if isinstance(u, str):
        low = u.lower()
        if low in ("true", "1", "yes"):
            return True
        if low in ("false", "0", "no"):
            return False
    return None


def parse_policy_document(blob: Any) -> dict[str, Any] | None:
    """Parse IAM policy JSON from string or dict (including heredoc-wrapped JSON)."""
    if isinstance(blob, dict):
        return blob
    if isinstance(blob, str):
        text = hcl_unwrap(blob)
        if not isinstance(text, str):
            text = str(text)
        try:
            out = json.loads(text)
            return out if isinstance(out, dict) else None
        except json.JSONDecodeError:
            pass
        if "{" in text and "}" in text:
            start = text.find("{")
            end = text.rfind("}") + 1
            try:
                out = json.loads(text[start:end])
            except json.JSONDecodeError:
                return None
            return out if isinstance(out, dict) else None
    return None
