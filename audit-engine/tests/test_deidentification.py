import re

import pytest

from audit_engine.deidentification import anonymize_record, pseudonymize_record, pseudonymize_value

SECRET = b"unit-test-secret-0123456789"


def test_pseudonym_is_deterministic_and_opaque():
    a = pseudonymize_value("alice", SECRET)
    assert a == pseudonymize_value("alice", SECRET)
    assert re.fullmatch(r"P-[0-9a-f]{16}", a)
    assert "alice" not in a


def test_pseudonym_depends_on_secret():
    assert pseudonymize_value("alice", SECRET) != pseudonymize_value("alice", b"another-secret-value-xyz")


def test_empty_secret_rejected():
    with pytest.raises(ValueError):
        pseudonymize_value("alice", b"")


def test_pseudonymize_record_replaces_only_configured_fields():
    out = pseudonymize_record({"actor": "alice", "role": "analyst"}, identifier_fields=("actor",), secret=SECRET)
    assert out["actor"].startswith("P-") and out["role"] == "analyst"


def test_pseudonymize_record_secret_is_keyword_only_and_required():
    with pytest.raises(TypeError):
        pseudonymize_record({"actor": "alice"}, ("actor",))  # no secret


def test_anonymize_record_removes_direct_identifiers_and_bands():
    out = anonymize_record({"name": "x", "age": 37, "purchase_amount": 200000, "keep": 1})
    assert out == {"keep": 1, "age_band": "30s", "purchase_band": "high"}
