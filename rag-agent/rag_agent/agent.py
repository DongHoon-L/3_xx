"""Rule-based tool routing. The LLM never chooses tools; the allowlist below is the whole capability set."""

from __future__ import annotations

import time
from dataclasses import dataclass
from uuid import uuid4

from .guard import DIRECT_SYSTEM_PROMPT, HARDENED_SYSTEM_PROMPT, check_question, filter_output, sanitize_context
from .llm import LLMClient, LLMError
from .retriever import Retriever

TOOLS: dict[str, str] = {
    "list_documents": "코퍼스 문서 id 목록 (LLM 미사용)",
    "rag_answer": "문서 검색 → SR-03 정화 → 문맥 기반 답변",
    "direct_answer": "문서 없이 일반 답변",
}
LIST_KEYWORDS = ("문서 목록", "documents", "목록")
NO_CONTEXT = "(관련 문서 없음)"


@dataclass(frozen=True)
class AgentTrace:
    request_id: str
    question: str
    status: str                       # answered | blocked | error
    tool: str
    reason: str
    guard_findings: tuple[str, ...]
    context_findings: tuple[str, ...]
    doc_ids: tuple[str, ...]
    contexts_sanitized: tuple[str, ...]
    answer: str | None
    llm_model: str
    latency_ms: int
    output_masked: bool
    error: str | None


class Agent:
    def __init__(self, retriever: Retriever, llm: LLMClient, top_k: int) -> None:
        self._retriever = retriever
        self._llm = llm
        self._top_k = top_k

    def choose_tool(self, question: str) -> tuple[str, str]:
        low = question.lower()
        if any(keyword in low for keyword in LIST_KEYWORDS):
            return "list_documents", "문서 목록 요청 키워드"
        hits = self._retriever.search(question, 1)
        if hits:
            return "rag_answer", f"코퍼스 관련도 {hits[0].score:.2f}"
        return "direct_answer", "코퍼스와 무관한 질문"

    def run(self, question: str) -> AgentTrace:
        request_id = str(uuid4())
        started = time.perf_counter()

        def finish(**fields) -> AgentTrace:
            return AgentTrace(request_id=request_id, question=question,
                              latency_ms=int((time.perf_counter() - started) * 1000), **fields)

        decision = check_question(question)
        if not decision.allowed:
            return finish(status="blocked", tool="none", reason="guard", guard_findings=decision.findings,
                          context_findings=(), doc_ids=(), contexts_sanitized=(), answer=None,
                          llm_model="", output_masked=False, error=None)

        tool, reason = self.choose_tool(question)
        try:
            if tool == "list_documents":
                raw, model, doc_ids, contexts, findings = self._list_documents()
            elif tool == "rag_answer":
                raw, model, doc_ids, contexts, findings = self._rag_answer(question)
            else:
                raw, model, doc_ids, contexts, findings = self._direct_answer(question)
        except LLMError as exc:
            return finish(status="error", tool=tool, reason=reason, guard_findings=(), context_findings=(),
                          doc_ids=(), contexts_sanitized=(), answer=None, llm_model="", output_masked=False,
                          error=exc.kind)

        answer, masked = filter_output(raw)
        return finish(status="answered", tool=tool, reason=reason, guard_findings=(), context_findings=findings,
                      doc_ids=doc_ids, contexts_sanitized=contexts, answer=answer, llm_model=model,
                      output_masked=masked, error=None)

    def _list_documents(self):
        ids = tuple(doc.doc_id for doc in self._retriever.documents)
        return "문서 목록: " + ", ".join(ids), "", ids, (), ()

    def _rag_answer(self, question: str):
        blocks: list[str] = []
        findings: list[str] = []
        ids: list[str] = []
        for hit in self._retriever.search(question, self._top_k):
            sanitized, hit_findings = sanitize_context(hit.document.text)
            blocks.append(f"[doc:{hit.document.doc_id}]\n{sanitized}")
            findings.extend(hit_findings)
            ids.append(hit.document.doc_id)
        context_block = "\n\n".join(blocks) if blocks else NO_CONTEXT
        result = self._llm.chat(HARDENED_SYSTEM_PROMPT, f"{context_block}\n\nQuestion: {question}")
        return result.text, result.model, tuple(ids), tuple(blocks), tuple(findings)

    def _direct_answer(self, question: str):
        result = self._llm.chat(DIRECT_SYSTEM_PROMPT, question)
        return result.text, result.model, (), (), ()
