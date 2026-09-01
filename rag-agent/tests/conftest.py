import base64

import pytest
from fastapi.testclient import TestClient

from rag_agent.api import create_app

TOKEN = "tok-alice-0123456789"


@pytest.fixture
def app_env(tmp_path, monkeypatch):
    values = {
        "AUDIT_PSEUDONYM_SECRET": "api-test-secret-0123456789",
        "AUDIT_KEK_B64": base64.b64encode(b"\x04" * 32).decode(),
        "AUDIT_CHAIN_PATH": str(tmp_path / "chain.jsonl"),
        "AUDIT_VAULT_PATH": str(tmp_path / "vault.json"),
        "RAG_API_KEYS": f"{TOKEN}:alice:analyst",
        "LLM_PROVIDER": "mock",
        # every optional variable pinned to its documented default: create_app() reads os.environ (and
        # loads .env), so without this a developer's local .env would change what the tests exercise
        "AUDIT_HASH_ALGORITHM": "sha256",
        "LLM_BASE_URL": "http://localhost:8080/v1",
        "LLM_MODEL": "local",
        "LLM_TIMEOUT_S": "120",
        "LLM_MAX_TOKENS": "512",
        "LLM_DISABLE_THINKING": "true",
        "RAG_TOP_K": "2",
        "RAG_MAX_QUESTION_CHARS": "2000",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    for key in ("LLM_API_KEY", "RAG_DOCUMENTS_PATH", "AUDIT_RETENTION_POLICY"):
        monkeypatch.delenv(key, raising=False)  # these have no fixed default value to pin
    return tmp_path


@pytest.fixture
def client(app_env):
    return TestClient(create_app())


@pytest.fixture
def auth():
    return {"Authorization": f"Bearer {TOKEN}"}
