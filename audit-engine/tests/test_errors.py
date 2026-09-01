import audit_engine
from audit_engine.errors import (
    AuditConfigError,
    AuditError,
    AuditStorageError,
    AuditValidationError,
    ChainCorruptError,
    KeyNotFoundError,
    SealIntegrityError,
)


def test_version():
    assert audit_engine.__version__ == "0.1.0"


def test_all_errors_derive_from_audit_error():
    for cls in (AuditConfigError, AuditStorageError, ChainCorruptError, KeyNotFoundError, SealIntegrityError):
        assert issubclass(cls, AuditError)


def test_validation_error_carries_field_and_reason():
    err = AuditValidationError("actor", "must be non-empty")
    assert isinstance(err, AuditError)
    assert err.field == "actor"
    assert err.reason == "must be non-empty"
    assert str(err) == "actor: must be non-empty"
