"""5W1H audit event schema with fail-closed validation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from .errors import AuditValidationError

TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
REQUIRED_FIELDS = ("timestamp", "actor", "action", "asset", "record_id")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime(TIMESTAMP_FORMAT)


def parse_timestamp(value: str) -> datetime:
    try:
        return datetime.strptime(value, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise AuditValidationError("timestamp", f"expected format {TIMESTAMP_FORMAT}") from exc


@dataclass(frozen=True)
class AuditEvent:
    timestamp: str    # When (UTC)
    actor: str        # Who
    role: str         # Who
    department: str   # Who
    action: str       # How
    asset: str        # What
    record_id: str    # What — correlation key
    source_ip: str    # Where
    purpose: str      # Why
    result: str       # Result
    details: dict[str, str] = field(default_factory=dict)

    def validate(self) -> None:
        for name in REQUIRED_FIELDS:
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise AuditValidationError(name, "must be a non-empty string")
        parse_timestamp(self.timestamp)
        if not isinstance(self.details, dict):
            raise AuditValidationError("details", "must be a dict")
        for key, value in self.details.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise AuditValidationError("details", "keys and values must be strings")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "AuditEvent":
        return cls(**data)
