"""Retention-period calculation from an external policy file. No silent fallbacks."""

from __future__ import annotations

import json
import os
from datetime import date, timedelta
from pathlib import Path

from .schema import AuditEvent, parse_timestamp

DEFAULT_POLICY_PATH = Path(__file__).parent / "policies" / "retention_policy.json"


class RetentionPolicy:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self._default = data["default_policy"]
        self._policies = data.get("policies", {})

    def for_event(self, event: AuditEvent) -> dict:
        policy = self._policies.get(event.action, self._default)
        days = int(policy["retention_days"])
        until = parse_timestamp(event.timestamp) + timedelta(days=days)   # raises AuditValidationError
        return {
            "retention_days": days,
            "retention_until": until.strftime("%Y-%m-%d"),
            "legal_basis": policy.get("legal_basis", self._default.get("legal_basis", "")),
            "category": policy.get("category", self._default.get("category", "")),
        }

    @staticmethod
    def is_expired(retention: dict, today: date) -> bool:
        return date.fromisoformat(retention["retention_until"]) < today
