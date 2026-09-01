"""Deterministic in-process TF-IDF retrieval. No embedding API, no network, no randomness."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Iterable

from .documents import Document

TOKEN_RE = re.compile(r"[0-9A-Za-z가-힣]+")
HANGUL_RE = re.compile(r"[가-힣]")


def tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    for token in TOKEN_RE.findall(text.lower()):
        tokens.append(token)
        if HANGUL_RE.search(token) and len(token) > 1:  # character bigrams help Korean particles
            tokens.extend(token[i:i + 2] for i in range(len(token) - 1))
    return tokens


@dataclass(frozen=True)
class Hit:
    document: Document
    score: float


class Retriever:
    def __init__(self, documents: Iterable[Document]) -> None:
        self._documents = list(documents)
        term_counts = [Counter(tokenize(doc.text)) for doc in self._documents]
        df: Counter[str] = Counter()
        for counts in term_counts:
            df.update(counts.keys())
        n = len(self._documents)
        self._idf = {term: math.log((1 + n) / (1 + freq)) + 1 for term, freq in df.items()}
        self._vectors = [self._vectorize(counts) for counts in term_counts]

    @property
    def documents(self) -> tuple[Document, ...]:
        return tuple(self._documents)

    def _vectorize(self, counts: Counter[str]) -> dict[str, float]:
        vector = {term: count * self._idf[term] for term, count in counts.items() if term in self._idf}
        norm = math.sqrt(sum(value * value for value in vector.values())) or 1.0
        return {term: value / norm for term, value in vector.items()}

    def search(self, query: str, top_k: int) -> list[Hit]:
        query_vector = self._vectorize(Counter(tokenize(query)))
        scored: list[Hit] = []
        for document, vector in zip(self._documents, self._vectors):
            score = sum(weight * vector.get(term, 0.0) for term, weight in query_vector.items())
            if score > 0:
                scored.append(Hit(document, score))
        scored.sort(key=lambda hit: -hit.score)  # stable sort keeps corpus order for ties
        return scored[:top_k]
