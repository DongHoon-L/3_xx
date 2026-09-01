"""Audit data pseudonymization and anonymization helpers.

Pseudonyms are deterministic per secret: the same identifier maps to the same
pseudonym, and they cannot be reproduced without the secret. The secret has no
default on purpose — it must be injected from configuration (fail closed).
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Mapping


def pseudonymize_value(value: Any, secret: bytes) -> str:
    """Return a stable, non-reversible pseudonym for ``value`` under ``secret``."""
    if not secret:
        raise ValueError("pseudonymization secret must not be empty")
    digest = hmac.new(secret, str(value).encode("utf-8"), hashlib.sha256).hexdigest()
    return f"P-{digest[:16]}"


def pseudonymize_record(
    record: Mapping[str, Any],
    identifier_fields: tuple[str, ...] = ("name", "email", "customer_id", "user_id"),
    *,
    secret: bytes,
) -> dict[str, Any]:
    """Copy a record while replacing configured direct identifiers."""
    result = dict(record)
    for field in identifier_fields:
        if field in result and result[field] not in (None, ""):
            result[field] = pseudonymize_value(result[field], secret)
    return result


def anonymize_record(
    record: Mapping[str, Any],
    remove_fields: tuple[str, ...] = ("name", "email", "phone", "address", "customer_id", "user_id"),
) -> dict[str, Any]:
    """Remove direct identifiers and generalize common quasi-identifiers."""
    result = {key: value for key, value in record.items() if key not in remove_fields}
    if isinstance(result.get("age"), int):
        result["age_band"] = f"{(result.pop('age') // 10) * 10}s"
    if isinstance(result.get("purchase_amount"), (int, float)):
        amount = result.pop("purchase_amount")
        result["purchase_band"] = "high" if amount >= 150000 else "standard"
    return result
