from pathlib import Path

import pytest

from rag_agent.config import Settings, build_llm_client
from rag_agent.documents import DEFAULT_DOCUMENTS_PATH
from rag_agent.llm import MockLLM, OpenAICompatClient

TOKEN = "tok-alice-0123456789"


def base_env(**overrides) -> dict:
    env = {"RAG_API_KEYS": f"{TOKEN}:alice:analyst"}
    env.update(overrides)
    return env


def test_defaults():
    s = Settings.from_env(base_env())
    assert s.principals[TOKEN].actor == "alice"
    assert s.llm_provider == "openai_compat" and s.llm_base_url == "http://localhost:8080/v1"
    assert s.llm_model == "local" and s.llm_api_key is None
    assert s.llm_timeout_s == 120.0 and s.llm_max_tokens == 512 and s.llm_disable_thinking is True
    assert s.documents_path == DEFAULT_DOCUMENTS_PATH and s.top_k == 2 and s.max_question_chars == 2000


def test_overrides(tmp_path):
    s = Settings.from_env(base_env(
        LLM_PROVIDER="mock", LLM_BASE_URL="http://10.0.0.5:9000/v1/", LLM_MODEL="qwen", LLM_API_KEY="k",
        LLM_TIMEOUT_S="30", LLM_MAX_TOKENS="128", LLM_DISABLE_THINKING="false",
        RAG_DOCUMENTS_PATH=str(tmp_path / "d.json"), RAG_TOP_K="5", RAG_MAX_QUESTION_CHARS="100",
    ))
    assert s.llm_provider == "mock" and s.llm_base_url == "http://10.0.0.5:9000/v1/" and s.llm_model == "qwen"
    assert s.llm_api_key == "k" and s.llm_timeout_s == 30.0 and s.llm_max_tokens == 128
    assert s.llm_disable_thinking is False and s.documents_path == Path(tmp_path / "d.json")
    assert s.top_k == 5 and s.max_question_chars == 100


@pytest.mark.parametrize("overrides", [
    {"RAG_API_KEYS": ""},
    {"LLM_PROVIDER": "gemini"},
    {"RAG_TOP_K": "0"}, {"RAG_TOP_K": "6"}, {"RAG_TOP_K": "two"},
    {"LLM_MAX_TOKENS": "0"}, {"LLM_TIMEOUT_S": "fast"},
    {"LLM_DISABLE_THINKING": "maybe"},
    {"RAG_MAX_QUESTION_CHARS": "0"},
])
def test_invalid_settings_rejected(overrides):
    env = base_env(**overrides)
    if overrides.get("RAG_API_KEYS") == "":
        env["RAG_API_KEYS"] = ""
    with pytest.raises(ValueError):
        Settings.from_env(env)


def test_missing_api_keys_rejected():
    with pytest.raises(ValueError):
        Settings.from_env({})


def test_repr_hides_tokens_and_api_key():
    text = repr(Settings.from_env(base_env(LLM_API_KEY="super-secret-llm-key")))
    assert TOKEN not in text and "super-secret-llm-key" not in text


def test_build_llm_client():
    assert isinstance(build_llm_client(Settings.from_env(base_env(LLM_PROVIDER="mock"))), MockLLM)
    assert isinstance(build_llm_client(Settings.from_env(base_env())), OpenAICompatClient)
