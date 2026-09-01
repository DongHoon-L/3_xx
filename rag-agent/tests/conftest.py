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
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    return tmp_path


@pytest.fixture
def client(app_env):
    return TestClient(create_app())


@pytest.fixture
def auth():
    return {"Authorization": f"Bearer {TOKEN}"}
