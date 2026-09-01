"""Static Bearer-token allowlist. Tokens are server-side secrets; identity is never client-asserted."""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass
from typing import Mapping

BEARER_RE = re.compile(r"(?i)^bearer\s+(.+)$")  # RFC 7235: the scheme name is case-insensitive


@dataclass(frozen=True)
class Principal:
    actor: str
    role: str
    department: str = "rag-users"


class AuthError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def parse_api_keys(raw: str) -> dict[str, Principal]:
    """Parse RAG_API_KEYS = "token:actor:role[,token:actor:role...]"."""
    keys: dict[str, Principal] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        parts = [p.strip() for p in item.split(":")]
        if len(parts) != 3 or not all(parts):
            raise ValueError("RAG_API_KEYS entries must look like token:actor:role")
        token, actor, role = parts
        if token in keys:
            raise ValueError("RAG_API_KEYS contains a duplicate token")
        keys[token] = Principal(actor=actor, role=role)
    if not keys:
        raise ValueError("RAG_API_KEYS must define at least one token")
    return keys


def authenticate(authorization: str | None, keys: Mapping[str, Principal]) -> Principal:
    match = BEARER_RE.match(authorization or "")
    if not match:
        raise AuthError("missing_token")  # any other scheme is treated as no token at all
    presented = match.group(1).strip().encode("utf-8")
    if not presented:
        raise AuthError("missing_token")
    matched: Principal | None = None
    for token, principal in keys.items():  # compare against every token: uniform timing
        if hmac.compare_digest(token.encode("utf-8"), presented):
            matched = principal
    if matched is None:
        raise AuthError("invalid_token")
    return matched
