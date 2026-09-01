"""Environment-driven settings for the agent. Invalid values raise ValueError at startup (fail closed)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .auth import Principal, parse_api_keys
from .documents import DEFAULT_DOCUMENTS_PATH
from .llm import LLMClient, MockLLM, OpenAICompatClient

LLM_PROVIDERS = ("openai_compat", "mock")
TOP_K_MAX = 5


def _int(source: Mapping[str, str], name: str, default: int, minimum: int, maximum: int | None = None) -> int:
    raw = source.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < minimum or (maximum is not None and value > maximum):
        raise ValueError(f"{name} must be between {minimum} and {maximum if maximum is not None else 'inf'}")
    return value


def _float(source: Mapping[str, str], name: str, default: float) -> float:
    try:
        value = float(source.get(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _bool(source: Mapping[str, str], name: str, default: bool) -> bool:
    raw = source.get(name, str(default)).strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"{name} must be true or false")


@dataclass(frozen=True, repr=False)
class Settings:
    principals: dict[str, Principal]
    llm_provider: str
    llm_base_url: str
    llm_model: str
    llm_api_key: str | None
    llm_timeout_s: float
    llm_max_tokens: int
    llm_disable_thinking: bool
    documents_path: Path
    top_k: int
    max_question_chars: int

    def __repr__(self) -> str:  # never print tokens or keys
        return (
            f"Settings(principals=<{len(self.principals)} tokens>, llm_provider={self.llm_provider!r}, "
            f"llm_base_url={self.llm_base_url!r}, llm_model={self.llm_model!r}, llm_api_key=<redacted>, "
            f"llm_timeout_s={self.llm_timeout_s}, llm_max_tokens={self.llm_max_tokens}, "
            f"llm_disable_thinking={self.llm_disable_thinking}, documents_path={str(self.documents_path)!r}, "
            f"top_k={self.top_k}, max_question_chars={self.max_question_chars})"
        )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        source = os.environ if env is None else env
        provider = source.get("LLM_PROVIDER", "openai_compat")
        if provider not in LLM_PROVIDERS:
            raise ValueError(f"LLM_PROVIDER must be one of {LLM_PROVIDERS}")
        return cls(
            principals=parse_api_keys(source.get("RAG_API_KEYS", "")),
            llm_provider=provider,
            llm_base_url=source.get("LLM_BASE_URL", "http://localhost:8080/v1"),
            llm_model=source.get("LLM_MODEL", "local"),
            llm_api_key=source.get("LLM_API_KEY") or None,
            llm_timeout_s=_float(source, "LLM_TIMEOUT_S", 120.0),
            llm_max_tokens=_int(source, "LLM_MAX_TOKENS", 512, minimum=1),
            llm_disable_thinking=_bool(source, "LLM_DISABLE_THINKING", True),
            documents_path=Path(source.get("RAG_DOCUMENTS_PATH", str(DEFAULT_DOCUMENTS_PATH))),
            top_k=_int(source, "RAG_TOP_K", 2, minimum=1, maximum=TOP_K_MAX),
            max_question_chars=_int(source, "RAG_MAX_QUESTION_CHARS", 2000, minimum=1),
        )


def build_llm_client(settings: Settings) -> LLMClient:
    if settings.llm_provider == "mock":
        return MockLLM()
    return OpenAICompatClient(
        base_url=settings.llm_base_url,
        model=settings.llm_model,
        api_key=settings.llm_api_key,
        timeout_s=settings.llm_timeout_s,
        max_tokens=settings.llm_max_tokens,
        disable_thinking=settings.llm_disable_thinking,
    )
