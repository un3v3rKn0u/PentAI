from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from pentai_core import __version__
from pentai_core.authorization import AuthorizationService, DomainError
from pentai_core.config import settings
from pentai_core.migrate import migrate


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    execution_enabled: bool


app = FastAPI(
    title="PentAI Local Core",
    version=__version__,
    docs_url=None,
    redoc_url=None,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:1420",
        "http://localhost:1420",
        "tauri://localhost",
        "http://tauri.localhost",
        "https://tauri.localhost",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ProgramRequest(BaseModel):
    name: str
    platform: str | None = None


class EngagementRequest(BaseModel):
    program_id: str
    effective_from: str
    expires_at: str
    timezone: str


class SourceRequest(BaseModel):
    program_id: str
    authority: str
    reference: str
    content: str
    effective_at: str | None = None


class ManifestRequest(BaseModel):
    engagement_id: str
    document: dict[str, Any]


class ApprovalRequest(BaseModel):
    approver_id: str
    decision: str = "approved"
    expires_at: str | None = None
    reason: str | None = None


class ActivationRequest(BaseModel):
    actor_id: str


class EvaluationRequest(BaseModel):
    engagement_id: str
    intent: dict[str, Any]


def service() -> AuthorizationService:
    migrate(settings.database_path)
    return AuthorizationService(settings.database_path)


def call[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except DomainError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


@app.get("/api/v1/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        version=__version__,
        environment=settings.environment,
        execution_enabled=False,
    )


@app.get("/api/v1/safety-state")
def safety_state() -> dict[str, object]:
    return {
        "active_policy": None,
        "network_attested": False,
        "execution_enabled": False,
        "reason": "Phase 0 scaffold: target execution is not implemented",
    }


@app.post("/api/v1/programs")
def create_program(request: ProgramRequest) -> dict[str, Any]:
    return call(lambda: service().create_program(request.name, request.platform))


@app.post("/api/v1/engagements")
def create_engagement(request: EngagementRequest) -> dict[str, Any]:
    return call(
        lambda: service().create_engagement(
            request.program_id,
            effective_from=request.effective_from,
            expires_at=request.expires_at,
            timezone=request.timezone,
        )
    )


@app.post("/api/v1/sources")
def import_source(request: SourceRequest) -> dict[str, Any]:
    return call(
        lambda: service().import_source(
            request.program_id,
            authority=request.authority,
            reference=request.reference,
            content=request.content,
            effective_at=request.effective_at,
        )
    )


@app.post("/api/v1/manifests")
def save_manifest(request: ManifestRequest) -> dict[str, Any]:
    return call(lambda: service().save_manifest(request.engagement_id, request.document))


@app.post("/api/v1/manifests/{manifest_id}/compile")
def compile_policy(manifest_id: str) -> dict[str, Any]:
    return call(lambda: service().compile_policy(manifest_id))


@app.post("/api/v1/policies/{policy_id}/approval")
def approve_policy(policy_id: str, request: ApprovalRequest) -> dict[str, Any]:
    return call(
        lambda: service().approve_policy(
            policy_id,
            approver_id=request.approver_id,
            decision=request.decision,
            expires_at=request.expires_at,
            reason=request.reason,
        )
    )


@app.post("/api/v1/policies/{policy_id}/activate")
def activate_policy(policy_id: str, request: ActivationRequest) -> dict[str, Any]:
    return call(lambda: service().activate_policy(policy_id, actor_id=request.actor_id))


@app.post("/api/v1/policy-decisions")
def evaluate_policy(request: EvaluationRequest) -> dict[str, Any]:
    return call(lambda: service().evaluate_intent(request.engagement_id, request.intent))


@app.get("/api/v1/audit")
def audit_events() -> dict[str, Any]:
    authorization = service()
    return {
        "events": authorization.audit_events(),
        "verification": authorization.verify_audit_chain(),
    }
