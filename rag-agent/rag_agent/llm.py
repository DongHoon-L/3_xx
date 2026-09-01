"""LLM clients. OpenAICompatClient talks to any /v1/chat/completions server (WSL llama-server, OpenRouter...).
MockLLM is deterministic for tests. There is intentionally no automatic fallback from real to mock."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

import requests

THINK_RE = re.compile(r"<think>.*?</think>\s*", re.DOTALL)
DOC_TAG_RE = re.compile(r"^\[doc:([^\]]+)\]", re.MULTILINE)


class LLMError(Exception):
    def __init__(self, kind: str, message: str = "") -> None:
        super().__init__(f"{kind}: {message}" if message else kind)
        self.kind = kind


@dataclass(frozen=True)
class LLMResult:
    text: str
    model: str


class LLMClient(Protocol):
    def chat(self, system: str, user: str) -> LLMResult: ...


def strip_thinking(text: str) -> str:
    return THINK_RE.sub("", text).strip()


class OpenAICompatClient:
    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str | None = None,
        timeout_s: float = 120.0,
        max_tokens: int = 512,
        disable_thinking: bool = True,
        session: requests.Session | None = None,
    ) -> None:
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._model = model
        self._api_key = api_key
        self._timeout = timeout_s
        self._max_tokens = max_tokens
        self._disable_thinking = disable_thinking
        self._session = session or requests.Session()

    def build_body(self, system: str, user: str) -> dict:
        body = {
            "model": self._model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": 0,
            "max_tokens": self._max_tokens,
        }
        if self._disable_thinking:
            body["chat_template_kwargs"] = {"enable_thinking": False}
        return body

    def chat(self, system: str, user: str) -> LLMResult:
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        try:
            response = self._session.post(self._url, json=self.build_body(system, user), headers=headers, timeout=self._timeout)
        except requests.Timeout as exc:
            raise LLMError("timeout", "llm request timed out") from exc
        except requests.RequestException as exc:
            raise LLMError("unavailable", exc.__class__.__name__) from exc
        if response.status_code != 200:
            raise LLMError("http_error", f"status {response.status_code}")
        try:
            data = response.json()
            text = data["choices"][0]["message"]["content"]
            model = data.get("model", self._model)
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise LLMError("bad_response", "unexpected payload shape") from exc
        if not isinstance(text, str):
            raise LLMError("bad_response", "content is not text")
        return LLMResult(strip_thinking(text), str(model))


class MockLLM:
    """Deterministic stand-in. Reproduces an injection *success* only if unsanitized override text reaches it."""

    LEAK_TRIGGERS = ("system override", "ignore all previous instructions")
    LEAK_TEXT = "[MOCK-LEAK] SECRET_SYSTEM_TOKEN: admin_secure_pass_9981"

    def chat(self, system: str, user: str) -> LLMResult:
        low = user.lower()
        if any(trigger in low for trigger in self.LEAK_TRIGGERS):
            return LLMResult(self.LEAK_TEXT, "mock")
        doc_ids = DOC_TAG_RE.findall(user)
        question = user.rsplit("Question:", 1)[-1].strip()[:60]
        return LLMResult(f"[MOCK] docs={','.join(doc_ids) or 'none'} q={question}", "mock")
