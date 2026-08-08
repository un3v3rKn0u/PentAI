from __future__ import annotations

import secrets
import threading
from base64 import b64decode
from binascii import Error as Base64Error
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from pentai_core import __version__
from pentai_core.authorization import AuthorizationService, DomainError
from pentai_core.config import Settings, allowed_origins
from pentai_core.migrate import migrate
from pentai_core.source_store import EncryptedSourceStore


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    execution_enabled: bool


@dataclass(frozen=True)
class LocalPrincipal:
    principal_id: str
    actor_type: str = "human"


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProgramRequest(StrictRequest):
    name: str
    platform: str | None = None
    program_url: str | None = None


class EngagementRequest(StrictRequest):
    program_id: str
    effective_from: str
    expires_at: str
    timezone: str


class SourceRequest(StrictRequest):
    program_id: str
    authority: str
    reference: str
    content: str
    effective_at: str | None = None
    source_kind: str = "pasted_text"
    media_type: str = "text/plain"
    source_version: str | None = None


class FileSourceRequest(StrictRequest):
    program_id: str
    authority: str
    filename: str
    media_type: str
    content_base64: str = Field(max_length=2_796_204)
    effective_at: str | None = None
    source_version: str | None = None


class ManifestRequest(StrictRequest):
    engagement_id: str
    document: dict[str, Any]


class ApprovalRequest(StrictRequest):
    decision: str = "approved"
    expires_at: str | None = None
    reason: str | None = None


class EvaluationRequest(StrictRequest):
    engagement_id: str
    intent: dict[str, Any]


def call[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except DomainError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


def _decode_file_content(encoded: str) -> bytes:
    try:
        return b64decode(encoded, validate=True)
    except (Base64Error, ValueError) as exc:
        raise DomainError("SOURCE_ENCODING_INVALID", "file content encoding is invalid") from exc


def _unauthorized() -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content={
            "detail": {
                "code": "AUTHENTICATION_REQUIRED",
                "message": "Authentication required",
            }
        },
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    runtime = settings or Settings.from_environment()
    runtime.validate()
    migrate(runtime.database_path)
    source_store = (
        EncryptedSourceStore(runtime.source_store_path, runtime.source_master_key)
        if runtime.source_master_key is not None
        else None
    )
    authorization = AuthorizationService(runtime.database_path, source_store=source_store)
    app = FastAPI(
        title="PentAI Local Core",
        version=__version__,
        docs_url=None,
        redoc_url=None,
    )
    app.state.shutdown_requested = threading.Event()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins(runtime),
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

    @app.middleware("http")
    async def authenticate(request: Request, call_next: Callable[..., Any]) -> Any:
        if not request.url.path.startswith("/api/v1/") or request.method == "OPTIONS":
            return await call_next(request)
        if runtime.test_mode:
            request.state.principal = LocalPrincipal("test-session")
            return await call_next(request)
        authorization_header = request.headers.get("authorization", "")
        prefix = "Bearer "
        if not authorization_header.startswith(prefix):
            return _unauthorized()
        supplied = authorization_header[len(prefix) :]
        expected = runtime.launch_credential or ""
        if not supplied or not secrets.compare_digest(supplied, expected):
            return _unauthorized()
        request.state.principal = LocalPrincipal("local-desktop-session")
        return await call_next(request)

    def principal(request: Request) -> LocalPrincipal:
        value = getattr(request.state, "principal", None)
        if not isinstance(value, LocalPrincipal):
            raise HTTPException(status_code=401, detail={"code": "AUTHENTICATION_REQUIRED"})
        return value

    @app.get("/api/v1/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(
            status="ok",
            version=__version__,
            environment=runtime.environment,
            execution_enabled=False,
        )

    @app.get("/api/v1/readiness")
    def readiness() -> dict[str, object]:
        return {"status": "ready", "execution_enabled": False}

    @app.post("/api/v1/shutdown")
    def shutdown() -> dict[str, str]:
        app.state.shutdown_requested.set()
        return {"status": "shutting_down"}

    @app.get("/api/v1/safety-state")
    def safety_state() -> dict[str, object]:
        return {
            "active_policy": None,
            "network_attested": False,
            "execution_enabled": False,
            "reason": "Phase 0 scaffold: target execution is not implemented",
        }

    @app.post("/api/v1/programs")
    def create_program(request: ProgramRequest, http_request: Request) -> dict[str, Any]:
        actor = principal(http_request)
        return call(
            lambda: authorization.create_program(
                request.name,
                request.platform,
                program_url=request.program_url,
                actor_id=actor.principal_id,
            )
        )

    @app.get("/api/v1/programs")
    def list_programs() -> dict[str, Any]:
        return {"programs": authorization.list_programs()}

    @app.post("/api/v1/engagements")
    def create_engagement(request: EngagementRequest) -> dict[str, Any]:
        return call(
            lambda: authorization.create_engagement(
                request.program_id,
                effective_from=request.effective_from,
                expires_at=request.expires_at,
                timezone=request.timezone,
            )
        )

    @app.post("/api/v1/sources")
    def import_source(request: SourceRequest, http_request: Request) -> dict[str, Any]:
        actor = principal(http_request)
        return call(
            lambda: authorization.import_source(
                request.program_id,
                authority=request.authority,
                reference=request.reference,
                content=request.content,
                effective_at=request.effective_at,
                source_kind=request.source_kind,
                media_type=request.media_type,
                source_version=request.source_version,
                actor_id=actor.principal_id,
            )
        )

    @app.get("/api/v1/programs/{program_id}/sources")
    def list_sources(program_id: str) -> dict[str, Any]:
        return {"sources": call(lambda: authorization.list_sources(program_id))}

    @app.post("/api/v1/sources/files")
    def import_file_source(
        request: FileSourceRequest, http_request: Request
    ) -> dict[str, Any]:
        actor = principal(http_request)
        return call(
            lambda: authorization.import_file_source(
                request.program_id,
                authority=request.authority,
                filename=request.filename,
                content=_decode_file_content(request.content_base64),
                media_type=request.media_type,
                effective_at=request.effective_at,
                source_version=request.source_version,
                actor_id=actor.principal_id,
            )
        )

    @app.post("/api/v1/manifests")
    def save_manifest(request: ManifestRequest) -> dict[str, Any]:
        return call(lambda: authorization.save_manifest(request.engagement_id, request.document))

    @app.post("/api/v1/manifests/{manifest_id}/compile")
    def compile_policy(manifest_id: str) -> dict[str, Any]:
        return call(lambda: authorization.compile_policy(manifest_id))

    @app.post("/api/v1/policies/{policy_id}/approval")
    def approve_policy(
        policy_id: str, approval: ApprovalRequest, request: Request
    ) -> dict[str, Any]:
        actor = principal(request)
        return call(
            lambda: authorization.approve_policy(
                policy_id,
                approver_id=actor.principal_id,
                decision=approval.decision,
                expires_at=approval.expires_at,
                reason=approval.reason,
            )
        )

    @app.post("/api/v1/policies/{policy_id}/activate")
    def activate_policy(policy_id: str, request: Request) -> dict[str, Any]:
        actor = principal(request)
        return call(lambda: authorization.activate_policy(policy_id, actor_id=actor.principal_id))

    @app.post("/api/v1/policy-decisions")
    def evaluate_policy(evaluation: EvaluationRequest) -> dict[str, Any]:
        return call(
            lambda: authorization.evaluate_intent(evaluation.engagement_id, evaluation.intent)
        )

    @app.get("/api/v1/audit")
    def audit_events() -> dict[str, Any]:
        return {
            "events": authorization.audit_events(),
            "verification": authorization.verify_audit_chain(),
        }

    return app
