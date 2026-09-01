import pytest

from rag_agent.auth import AuthError, Principal, authenticate, parse_api_keys

KEYS = parse_api_keys("tok-alice-0123456789:alice:analyst, tok-bob-9876543210:bob:admin")


def test_parse_api_keys():
    assert KEYS == {
        "tok-alice-0123456789": Principal("alice", "analyst", "rag-users"),
        "tok-bob-9876543210": Principal("bob", "admin", "rag-users"),
    }


@pytest.mark.parametrize("raw", ["", "   ", "tok:alice", "tok:alice:analyst:extra", "tok::analyst", "t1:a:r,t1:b:r"])
def test_parse_api_keys_rejects_bad_input(raw):
    with pytest.raises(ValueError):
        parse_api_keys(raw)


def test_authenticate_success():
    assert authenticate("Bearer tok-bob-9876543210", KEYS).actor == "bob"


@pytest.mark.parametrize("header,reason", [
    (None, "missing_token"),
    ("", "missing_token"),
    ("Basic abc", "missing_token"),
    ("Bearer ", "missing_token"),
    ("Bearer wrong-token-000000000", "invalid_token"),
    ("Bearer tok-alice-012345678", "invalid_token"),  # prefix of a real token
])
def test_authenticate_failures(header, reason):
    with pytest.raises(AuthError) as exc:
        authenticate(header, KEYS)
    assert exc.value.reason == reason
