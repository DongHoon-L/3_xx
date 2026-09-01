"""PII detection and irreversible log masking utilities."""

from __future__ import annotations

import re
from typing import Any


PATTERNS = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "phone": re.compile(r"01[0-9]-\d{3,4}-\d{4}"),
    "rrn": re.compile(r"\d{6}-\d{7}"),
    "card": re.compile(r"(?<!\d)(?:\d{4}[- ]?){3}\d{4}(?!\d)"),
}

DIRECT_FIELD_LABELS = {
    "name": "name",
    "email": "email",
    "phone": "phone",
    "address": "address",
}


def mask_value(label: str) -> str:
    return f"[{label.upper()}_MASKED]"


def mask_text(text: str) -> tuple[str, list[dict[str, str]]]:
    """Mask known PII patterns and return masked text plus findings."""
    masked = text
    findings: list[dict[str, str]] = []
    for label, pattern in PATTERNS.items():
        matches = pattern.findall(masked)
        for match in matches:
            findings.append({"type": label, "value": match})
        masked = pattern.sub(mask_value(label), masked)
    return masked, findings


def mask_record(value: Any, key_name: str | None = None) -> tuple[Any, list[dict[str, str]]]:
    """Recursively mask strings in dictionaries/lists without mutating input."""
    direct_label = DIRECT_FIELD_LABELS.get((key_name or "").lower())
    if direct_label and isinstance(value, str):
        return mask_value(direct_label), [{"type": direct_label, "value": value}]
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        findings: list[dict[str, str]] = []
        for key, nested in value.items():
            output[key], nested_findings = mask_record(nested, key)
            findings.extend(nested_findings)
        return output, findings
    if isinstance(value, list):
        output = []
        findings = []
        for nested in value:
            masked, nested_findings = mask_record(nested, key_name)
            output.append(masked)
            findings.extend(nested_findings)
        return output, findings
    if isinstance(value, str):
        return mask_text(value)
    return value, []
