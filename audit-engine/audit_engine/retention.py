"""Retention-period calculation from an external policy file. No silent fallbacks."""

from __future__ import annotations

import json
import os
from datetime import date, timedelta
from pathlib import Path

from .errors import AuditConfigError
from .schema import AuditEvent, parse_timestamp

DEFAULT_POLICY_PATH = Path(__file__).parent / "policies" / "retention_policy.json"


def _validate_policy(path: Path, name: str, policy: object) -> None:
    if not isinstance(policy, dict):
        raise AuditConfigError(f"retention policy {path}: {name} must be a JSON object")
    days = policy.get("retention_days")
    if not isinstance(days, int) or isinstance(days, bool):
        raise AuditConfigError(f"retention policy {path}: {name}.retention_days must be an integer")


class RetentionPolicy:
    """Validated at construction so `for_event` cannot raise KeyError/TypeError on a bad policy file."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        file = Path(path)
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except OSError as exc:
            raise AuditConfigError(f"cannot read retention policy {file}: {exc.__class__.__name__}") from exc
        except ValueError as exc:
            raise AuditConfigError(f"retention policy {file} is not valid JSON") from exc
        if not isinstance(data, dict):
            raise AuditConfigError(f"retention policy {file} must be a JSON object")
        policies = data.get("policies", {})
        if not isinstance(policies, dict):
            raise AuditConfigError(f"retention policy {file}: policies must be a JSON object")
        _validate_policy(file, "default_policy", data.get("default_policy"))
        for action, policy in policies.items():
            _validate_policy(file, f"policies.{action}", policy)
        self._default = data["default_policy"]
        self._policies = policies

    def for_event(self, event: AuditEvent) -> dict:
        policy = self._policies.get(event.action, self._default)
        days = policy["retention_days"]
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
