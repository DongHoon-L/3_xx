"""audit_engine — tamper-evident 5W1H audit engine.

Public API:
    AuditRecorder.from_env().record(event, sensitive)   # add-on entry point
    HashChain / KeyVault / RetentionPolicy              # building blocks
    python -m audit_engine verify|report|shred|unseal|keygen
"""

from .chain import ChainEntry, ChainVerification, HashChain, canonical_json
from .config import AuditConfig
from .crypto import KeyVault, generate_key, seal, unseal
from .deidentification import anonymize_record, pseudonymize_record, pseudonymize_value
from .errors import (
    AuditConfigError,
    AuditError,
    AuditStorageError,
    AuditValidationError,
    ChainCorruptError,
    KeyNotFoundError,
    SealIntegrityError,
)
from .masking import mask_record, mask_text
from .recorder import AuditRecorder
from .retention import RetentionPolicy
from .schema import AuditEvent, utc_now

__version__ = "0.1.0"

__all__ = [
    "AuditConfig", "AuditConfigError", "AuditError", "AuditEvent", "AuditRecorder", "AuditStorageError",
    "AuditValidationError", "ChainCorruptError", "ChainEntry", "ChainVerification", "HashChain", "KeyNotFoundError",
    "KeyVault", "RetentionPolicy", "SealIntegrityError", "anonymize_record", "canonical_json", "generate_key",
    "mask_record", "mask_text", "pseudonymize_record", "pseudonymize_value", "seal", "unseal", "utc_now",
]
