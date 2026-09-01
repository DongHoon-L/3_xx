import pytest

from audit_engine.errors import AuditValidationError
from audit_engine.schema import TIMESTAMP_FORMAT, AuditEvent, parse_timestamp, utc_now


def make_event(**overrides) -> AuditEvent:
    base = dict(
        timestamp="2026-09-01T03:00:00Z",
        actor="alice",
        role="analyst",
        department="rag-users",
        action="agent_query",
        asset="rag-agent/agent",
        record_id="req-001",
        source_ip="127.0.0.1",
        purpose="what is the weather",
        result="answered",
        details={"tool": "rag_answer"},
    )
    base.update(overrides)
    return AuditEvent(**base)


def test_valid_event_passes():
    make_event().validate()


@pytest.mark.parametrize("field", ["actor", "action", "asset", "record_id", "timestamp"])
def test_required_fields_reject_blank(field):
    with pytest.raises(AuditValidationError) as exc:
        make_event(**{field: "   "}).validate()
    assert exc.value.field == field


@pytest.mark.parametrize("bad", ["2026-09-01 03:00:00", "2026-09-01T03:00:00+09:00", "not-a-date", "2026-09-01T03:00:00"])
def test_timestamp_must_be_utc_z_format(bad):
    with pytest.raises(AuditValidationError) as exc:
        make_event(timestamp=bad).validate()
    assert exc.value.field == "timestamp"


def test_details_must_be_flat_string_map():
    with pytest.raises(AuditValidationError) as exc:
        make_event(details={"latency_ms": 12}).validate()
    assert exc.value.field == "details"


def test_utc_now_matches_format():
    parse_timestamp(utc_now())
    assert utc_now().endswith("Z")
    assert TIMESTAMP_FORMAT == "%Y-%m-%dT%H:%M:%SZ"


def test_round_trip_dict():
    event = make_event()
    assert AuditEvent.from_dict(event.to_dict()) == event
    assert event.to_dict()["details"] == {"tool": "rag_answer"}
