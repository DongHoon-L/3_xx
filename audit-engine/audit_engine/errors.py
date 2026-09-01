"""Exception hierarchy for audit-engine. Callers catch AuditError to fail closed."""


class AuditError(Exception):
    """Base class for every audit-engine failure."""


class AuditValidationError(AuditError):
    """An AuditEvent (or a value derived from one) failed validation."""

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"{field}: {reason}")
        self.field = field
        self.reason = reason


class AuditConfigError(AuditError):
    """Required configuration is missing or invalid."""


class ChainCorruptError(AuditError):
    """The on-disk hash chain failed verification; appending is refused."""


class AuditStorageError(AuditError):
    """A chain or vault file could not be read or written."""


class KeyNotFoundError(AuditError):
    """The data key for a record is absent from the vault (never stored or shredded)."""


class SealIntegrityError(AuditError):
    """AES-GCM authentication failed or the sealed payload is malformed."""
