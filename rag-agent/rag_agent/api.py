"""HTTP surface. Order per request: authenticate → run agent → audit → respond.
Fail closed: if the audit record cannot be written, the answer is withheld (503)."""

from __future__ import annotations

import logging

from audit_engine import AuditError, AuditRecorder
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .agent import TOOLS, Agent
from .audit_hook import AuditHook
from .auth import AuthError, Principal, authenticate
from .config import Settings, build_llm_client
from .documents import load_documents
from .llm import LLMClient
from .retriever import Retriever

log = logging.getLogger("rag_agent")


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
            audited(lambda: hook.record_auth_denied(ip, exc.reason))
            log.warning("auth_denied reason=%s ip=%s", exc.reason, ip)
            raise HTTPException(status_code=401, detail=exc.reason) from exc

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
    def ask(body: AgentRequest, request: Request):
        principal = require_principal(request)
        question = body.question.strip()
        if not question or len(question) > settings.max_question_chars:
            raise HTTPException(status_code=400, detail=f"question must be 1..{settings.max_question_chars} characters")

        trace = agent.run(question)
        audited(lambda: hook.record_query(trace, principal, client_ip(request)))
        log.info("agent_query request_id=%s actor=%s status=%s tool=%s latency_ms=%d",
                 trace.request_id, principal.actor, trace.status, trace.tool, trace.latency_ms)

        if trace.status == "blocked":
            return JSONResponse(status_code=403, content={
                "request_id": trace.request_id, "status": "blocked", "findings": list(trace.guard_findings)})
        if trace.status == "error":
            return JSONResponse(status_code=502, content={
                "request_id": trace.request_id, "status": "error", "error": trace.error})
        return {"request_id": trace.request_id, "status": "answered", "tool": trace.tool,
                "reason": trace.reason, "answer": trace.answer}

    return app
