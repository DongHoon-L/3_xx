"""HTTP surface. Order per request: bound the body → authenticate → validate → run agent → audit → respond.
Fail closed: if the audit record cannot be written, the answer is withheld (503)."""

from __future__ import annotations

import logging
from uuid import uuid4

from audit_engine import AuditError, AuditRecorder
from dotenv import load_dotenv
from fastapi import Body, Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .agent import TOOLS, Agent, AgentTrace
from .audit_hook import AuditHook
from .auth import AuthError, Principal, authenticate
from .config import Settings, build_llm_client
from .documents import load_documents
from .llm import LLMClient
from .retriever import Retriever

log = logging.getLogger("rag_agent")

MAX_BODY_BYTES = 64 * 1024


class AgentRequest(BaseModel):
    question: str


def create_app(
    settings: Settings | None = None,
    recorder: AuditRecorder | None = None,
    llm: LLMClient | None = None,
) -> FastAPI:
    load_dotenv(override=False)  # .env never overrides explicit environment
    settings = settings or Settings.from_env()
    recorder = recorder or AuditRecorder.from_env()  # raises AuditConfigError → process refuses to start
    retriever = Retriever(load_documents(settings.documents_path))
    agent = Agent(retriever, llm or build_llm_client(settings), settings.top_k)
    hook = AuditHook(recorder)

    app = FastAPI(title="RAG Agent (audited)", version="0.1.0")

    @app.middleware("http")
    async def limit_agent_body(request: Request, call_next):
        """Bound POST /agent before the body is read, so an anonymous flood cannot buy memory or an audit
        write. Not audited: the request never reached authentication. A body whose size cannot be known up
        front (chunked, or a malformed Content-Length) is refused rather than read."""
        if request.method == "POST" and request.url.path == "/agent":
            declared = request.headers.get("content-length")
            chunked = "chunked" in request.headers.get("transfer-encoding", "").lower()
            oversized = declared is not None and (not declared.isdigit() or int(declared) > MAX_BODY_BYTES)
            if chunked or oversized:
                return JSONResponse(status_code=413, content={"detail": "body too large"})
        return await call_next(request)

    def client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def audited(action):
        try:
            return action()
        except AuditError as exc:
            log.error("audit_unavailable error=%s", exc.__class__.__name__)
            raise HTTPException(status_code=503, detail="audit_unavailable") from exc

    def require_principal(request: Request) -> Principal:
        try:
            return authenticate(request.headers.get("authorization"), settings.principals)
        except AuthError as exc:
            ip = client_ip(request)
            entry = audited(lambda: hook.record_auth_denied(ip, exc.reason))
            log.warning("auth_denied reason=%s ip=%s audit_seq=%d audit_hash=%s",
                        exc.reason, ip, entry.seq, entry.entry_hash)
            raise HTTPException(status_code=401, detail=exc.reason) from exc

    # The endpoints below are intentionally sync `def` (FastAPI runs them in a worker thread): record()
    # fsyncs and the LLM call can block for up to LLM_TIMEOUT_S — do not convert them to `async def`.

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.get("/tools")
    def tools(request: Request) -> dict:
        require_principal(request)
        return {"tools": [{"name": name, "description": description} for name, description in TOOLS.items()]}

    @app.get("/documents")
    def documents(request: Request) -> dict:
        require_principal(request)
        ids = [doc.doc_id for doc in retriever.documents]
        return {"count": len(ids), "doc_ids": ids}

    @app.post("/agent")
    def ask(request: Request, principal: Principal = Depends(require_principal), body: AgentRequest = Body(...)):
        # require_principal is a dependency so that an unauthenticated caller gets the audited 401 before
        # pydantic can answer with a 422 field error.
        question = body.question.strip()
        if not question or len(question) > settings.max_question_chars:
            raise HTTPException(status_code=400, detail=f"question must be 1..{settings.max_question_chars} characters")

        ip = client_ip(request)
        try:
            trace = agent.run(question)
        except Exception as exc:  # an unexpected failure must not leave the request unaudited
            trace = AgentTrace(request_id=str(uuid4()), question=question, status="error", tool="none",
                               reason="internal", guard_findings=(), context_findings=(), doc_ids=(),
                               contexts_sanitized=(), answer=None, llm_model="", latency_ms=0,
                               output_masked=False, error="internal")
            entry = audited(lambda: hook.record_query(trace, principal, ip))
            log.error("agent_query request_id=%s actor=%s status=error result=error:internal error=%s "
                      "audit_seq=%d audit_hash=%s", trace.request_id, principal.actor,
                      exc.__class__.__name__, entry.seq, entry.entry_hash)
            raise  # FastAPI → 500; the exception text never reaches the client

        entry = audited(lambda: hook.record_query(trace, principal, ip))
        log.info("agent_query request_id=%s actor=%s status=%s tool=%s latency_ms=%d audit_seq=%d audit_hash=%s",
                 trace.request_id, principal.actor, trace.status, trace.tool, trace.latency_ms,
                 entry.seq, entry.entry_hash)

        if trace.status == "blocked":
            return JSONResponse(status_code=403, content={
                "request_id": trace.request_id, "status": "blocked", "findings": list(trace.guard_findings)})
        if trace.status == "error":
            return JSONResponse(status_code=502, content={
                "request_id": trace.request_id, "status": "error", "error": trace.error})
        return {"request_id": trace.request_id, "status": "answered", "tool": trace.tool,
                "reason": trace.reason, "answer": trace.answer}

    return app
