from datetime import date

import pytest

from audit_engine.errors import AuditValidationError
from audit_engine.retention import DEFAULT_POLICY_PATH, RetentionPolicy
from audit_engine.schema import AuditEvent


def make_event(action: str, timestamp: str = "2026-09-01T03:00:00Z") -> AuditEvent:
    return AuditEvent(timestamp, "alice", "analyst", "rag-users", action, "rag-agent/agent", "r1", "127.0.0.1", "-", "ok")


@pytest.fixture
def policy() -> RetentionPolicy:
    return RetentionPolicy(DEFAULT_POLICY_PATH)


@pytest.mark.parametrize("action,days,until", [
    ("agent_query", 365, "2027-09-01"),
    ("agent_query_blocked", 1095, "2029-08-31"),
    ("auth_denied", 1095, "2029-08-31"),
    ("audit_shred", 1825, "2031-08-31"),
    ("audit_unseal", 1825, "2031-08-31"),
    ("unknown_action", 365, "2027-09-01"),
])
def test_retention_days_and_until(policy, action, days, until):
    result = policy.for_event(make_event(action))
    assert result["retention_days"] == days
    assert result["retention_until"] == until
    assert result["legal_basis"] and result["category"]


def test_malformed_timestamp_raises_instead_of_using_now(policy):
    with pytest.raises(AuditValidationError):
        policy.for_event(make_event("agent_query", timestamp="2026/09/01"))


def test_is_expired():
    retention = {"retention_until": "2027-09-01"}
    assert RetentionPolicy.is_expired(retention, date(2027, 9, 2)) is True
    assert RetentionPolicy.is_expired(retention, date(2027, 9, 1)) is False
