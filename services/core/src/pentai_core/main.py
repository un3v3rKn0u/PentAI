from __future__ import annotations

from collections.abc import Callable

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from pentai_core import __version__
from pentai_core.authorization import AuthorizationError, AuthorizationService
from pentai_core.config import settings


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
    allow_origins=["http://127.0.0.1:1420", "tauri://localhost"],
    allow_methods=["GET", "POST"],
    allow_headers=["content-type"],
)
authorization = AuthorizationService(settings.database_path)


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


def _run(operation: Callable[[], object]) -> object:
    try:
        return operation()
    except AuthorizationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/v1/programs")
def create_program(body: dict[str, object]) -> object:
    platform = body.get("platform")
    return _run(
        lambda: authorization.create_program(
            str(body.get("name", "")), str(platform) if platform is not None else None
        )
    )


@app.post("/api/v1/programs/{program_id}/sources")
def import_source(program_id: str, body: dict[str, object]) -> object:
    return _run(
        lambda: authorization.import_source(
            program_id,
            reference=str(body.get("reference", "")),
            authority=str(body.get("authority", "")),
            content=str(body.get("content", "")),
        )
    )


@app.post("/api/v1/programs/{program_id}/engagements")
def create_engagement(program_id: str, body: dict[str, object]) -> object:
    return _run(lambda: authorization.create_engagement(program_id, body))


@app.post("/api/v1/engagements/{engagement_id}/manifests")
def save_manifest(engagement_id: str, body: dict[str, object]) -> object:
    return _run(lambda: authorization.save_manifest(engagement_id, body))


@app.post("/api/v1/manifests/{manifest_id}/compile")
def compile_policy(manifest_id: str) -> object:
    return _run(lambda: authorization.compile(manifest_id))


@app.post("/api/v1/policies/{policy_id}/approval")
def approve_policy(policy_id: str, body: dict[str, object]) -> object:
    return _run(
        lambda: authorization.approve(
            policy_id,
            approver_id=str(body.get("approver_id", "")),
            expires_at=str(body.get("expires_at", "")),
            decision=str(body.get("decision", "approved")),
        )
    )


@app.post("/api/v1/policies/{policy_id}/activate")
def activate_policy(policy_id: str, body: dict[str, object]) -> object:
    return _run(lambda: authorization.activate(policy_id, actor_id=str(body.get("actor_id", ""))))


@app.post("/api/v1/policies/{policy_id}/revoke")
def revoke_policy(policy_id: str, body: dict[str, object]) -> object:
    return _run(lambda: authorization.revoke(policy_id, actor_id=str(body.get("actor_id", ""))))


@app.post("/api/v1/policies/{policy_id}/evaluate")
def evaluate_intent(policy_id: str, body: dict[str, object]) -> object:
    return _run(lambda: authorization.evaluate_intent(policy_id, body))


@app.get("/api/v1/audit")
def audit_events() -> object:
    return {
        "events": authorization.audit_events(),
        "verification": authorization.verify_audit_chain(),
    }
