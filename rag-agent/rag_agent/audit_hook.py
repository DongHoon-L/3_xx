"""The only place rag_agent talks to audit_engine. Maps one request to one 5W1H event (+ sealed payload)."""

from __future__ import annotations

import hashlib
from uuid import uuid4

from audit_engine import AuditEvent, AuditRecorder, ChainEntry, utc_now

from .agent import AgentTrace
from .auth import Principal

ASSET = "rag-agent/agent"
PURPOSE_MAX_CHARS = 200


def _sha256(text: str | None) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest() if text else ""


class AuditHook:
    def __init__(self, recorder: AuditRecorder) -> None:
        self._recorder = recorder

    def record_query(self, trace: AgentTrace, principal: Principal, source_ip: str) -> ChainEntry:
        if trace.status == "answered":
            result = "answered"
        elif trace.status == "blocked":
            result = "blocked:" + ",".join(trace.guard_findings)
        else:
            result = f"error:{trace.error}"
        event = AuditEvent(
            timestamp=utc_now(),
            actor=principal.actor,
            role=principal.role,
            department=principal.department,
            action="agent_query_blocked" if trace.status == "blocked" else "agent_query",
            asset=ASSET,
            record_id=trace.request_id,
            source_ip=source_ip,
            purpose=trace.question[:PURPOSE_MAX_CHARS],
            result=result,
            details={
                "tool": trace.tool,
                "reason": trace.reason,
                "doc_ids": ",".join(trace.doc_ids),
                "guard_findings": ",".join(trace.guard_findings),
                "context_findings": ",".join(trace.context_findings),
                "llm_model": trace.llm_model,
                "latency_ms": str(trace.latency_ms),
                "answer_sha256": _sha256(trace.answer),
                "output_masked": str(trace.output_masked).lower(),
            },
        )
        sensitive = {"question": trace.question, "answer": trace.answer or "", "contexts": list(trace.contexts_sanitized)}
        return self._recorder.record(event, sensitive)

    def record_auth_denied(self, source_ip: str, reason: str) -> ChainEntry:
        event = AuditEvent(
            timestamp=utc_now(), actor="anonymous", role="unauthenticated", department="-",
            action="auth_denied", asset=ASSET, record_id=str(uuid4()), source_ip=source_ip,
            purpose="-", result=f"denied:{reason}", details={"reason": reason},
        )
        return self._recorder.record(event)
