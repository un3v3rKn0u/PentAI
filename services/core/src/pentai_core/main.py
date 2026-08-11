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
from pentai_core.controlled_dns_composition import compose_controlled_resolver_provider
from pentai_core.gateway_runtime_composition import compose_gateway_runtime_supervisor
from pentai_core.gateway_runtime_supervisor import RuntimeSupervisorControl
from pentai_core.migrate import migrate
from pentai_core.network_attestation_adapters import SystemRouteProbe
from pentai_core.network_profile_setup import (
    NetworkProfileSetupError,
    NetworkProfileSetupService,
)
from pentai_core.network_safety_composition import compose_network_safety_supervisor
from pentai_core.network_safety_supervisor import (
    NetworkSafetySupervisorControl,
)
from pentai_core.policy_signing import PolicySigner
from pentai_core.source_store import EncryptedSourceStore
from pentai_core.url_acquisition import AcquisitionError, UrlAcquirer
from pentai_core.workflow import AssessmentWorkflowService, WorkflowError


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


class UrlSourceRequest(StrictRequest):
    program_id: str
    authority: str
    url: str = Field(max_length=2048)
    effective_at: str | None = None
    source_version: str | None = None


class ManifestRequest(StrictRequest):
    engagement_id: str
    document: dict[str, Any]


class ApprovalRequest(StrictRequest):
    decision: str = "approved"
    expires_at: str | None = None
    reason: str | None = None


class RevocationRequest(StrictRequest):
    reason: str = Field(min_length=1, max_length=500)


class EvaluationRequest(StrictRequest):
    engagement_id: str
    intent: dict[str, Any]


class GrantRequest(StrictRequest):
    decision_id: str
    audience: str = "pentai-execution-broker"


class GrantConsumptionRequest(StrictRequest):
    grant: dict[str, Any]
    intent: dict[str, Any]
    audience: str


class SafetyRequest(StrictRequest):
    status: str
    reason: str = Field(min_length=1, max_length=500)


class NetworkProfileActivationRequest(StrictRequest):
    proposal_id: str
    confirm_route: bool
    resolver_mode: str
    registered_source_ipv4: list[str] = Field(default_factory=list, max_length=16)
    registered_source_ipv6: list[str] = Field(default_factory=list, max_length=16)
    ipv6_mode: str = "disabled"


class NetworkProfileRevocationRequest(StrictRequest):
    reason: str = Field(min_length=1, max_length=500)


class WorkflowCreateRequest(StrictRequest):
    engagement_id: str
    idempotency_key: str = Field(min_length=16, max_length=128)


class WorkflowTransitionRequest(StrictRequest):
    target_status: str
    expected_version: int = Field(ge=1)


class WorkflowTaskRequest(StrictRequest):
    task_kind: str
    idempotency_key: str = Field(min_length=16, max_length=128)
    input_refs: list[str] = Field(default_factory=list, max_length=64)
    parent_task_id: str | None = None


class WorkflowTaskClaimRequest(StrictRequest):
    expected_version: int = Field(ge=1)
    lease_seconds: int = Field(ge=5, le=300)


class WorkflowTaskLeaseRequest(StrictRequest):
    expected_version: int = Field(ge=2)
    lease_token: str = Field(min_length=32, max_length=128)
    lease_seconds: int = Field(ge=5, le=300)


class WorkflowTaskCheckpointRequest(StrictRequest):
    expected_version: int = Field(ge=2)
    lease_token: str = Field(min_length=32, max_length=128)
    progress: int = Field(ge=0, le=100)
    output_refs: list[str] = Field(default_factory=list, max_length=64)


class WorkflowTaskFinalizeRequest(StrictRequest):
    operation: str
    expected_version: int = Field(ge=2)
    lease_token: str = Field(min_length=32, max_length=128)
    idempotency_key: str = Field(min_length=16, max_length=128)
    error_code: str | None = None
    retry_delay_seconds: int = Field(default=0, ge=0, le=3600)


def call[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except DomainError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


def workflow_call[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except WorkflowError as exc:
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


def create_app(
    settings: Settings | None = None,
    *,
    runtime_supervisor: RuntimeSupervisorControl | None = None,
    network_safety_supervisor: NetworkSafetySupervisorControl | None = None,
    network_profile_setup_service: NetworkProfileSetupService | None = None,
) -> FastAPI:
    runtime = settings or Settings.from_environment()
    runtime.validate()
    migrate(runtime.database_path)
    source_store = (
        EncryptedSourceStore(runtime.source_store_path, runtime.source_master_key)
        if runtime.source_master_key is not None
        else None
    )
    signer = PolicySigner(runtime.policy_signing_key) if runtime.policy_signing_key else None
    authorization = AuthorizationService(
        runtime.database_path, source_store=source_store, policy_signer=signer
    )
    audit_verification = authorization.verify_audit_chain()
    if not audit_verification["valid"]:
        raise RuntimeError("audit ledger verification failed; startup is denied")
    workflows = AssessmentWorkflowService(runtime.database_path)
    controlled_resolver_provider = compose_controlled_resolver_provider(
        settings=runtime, profile_control=authorization
    )
    authorization.recover_startup()
    workflows.recover_startup()
    supervisor = runtime_supervisor or compose_gateway_runtime_supervisor(
        settings=runtime, safety_control=authorization
    )
    supervisor.start()
    network_supervisor = network_safety_supervisor or compose_network_safety_supervisor(
        settings=runtime, safety_control=authorization
    )
    network_supervisor.start()
    profile_setup = network_profile_setup_service or NetworkProfileSetupService(SystemRouteProbe())
    app = FastAPI(
        title="PentAI Local Core",
        version=__version__,
        docs_url=None,
        redoc_url=None,
    )
    app.state.shutdown_requested = threading.Event()
    app.state.runtime_supervisor = supervisor
    app.state.network_safety_supervisor = network_supervisor
    app.state.controlled_resolver_provider = controlled_resolver_provider
    app.state.network_profile_setup_service = profile_setup
    app.state.assessment_workflows = workflows
    app.router.add_event_handler("shutdown", network_supervisor.stop)
    app.router.add_event_handler("shutdown", supervisor.stop)
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
        runtime_status = supervisor.status()
        network_status = network_supervisor.status()
        return HealthResponse(
            status=(
                "degraded"
                if "degraded" in {runtime_status["status"], network_status["status"]}
                else "ok"
            ),
            version=__version__,
            environment=runtime.environment,
            execution_enabled=False,
        )

    @app.get("/api/v1/readiness", response_model=None)
    def readiness() -> Any:
        runtime_status = supervisor.status()
        network_status = network_supervisor.status()
        if runtime_status["status"] == "degraded" or network_status["status"] == "degraded":
            reason_code = (
                runtime_status["reason_code"]
                if runtime_status["status"] == "degraded"
                else network_status["reason_code"]
            )
            return JSONResponse(
                status_code=503,
                content={
                    "status": "degraded",
                    "reason_code": reason_code,
                    "execution_enabled": False,
                },
            )
        return {"status": "ready", "execution_enabled": False}

    @app.get("/api/v1/runtime-supervision")
    def runtime_supervision() -> dict[str, object]:
        return supervisor.status()

    @app.get("/api/v1/network-safety-supervision")
    def network_safety_supervision() -> dict[str, object]:
        return network_supervisor.status()

    @app.get("/api/v1/network-profile-proposal")
    def network_profile_proposal() -> dict[str, Any]:
        try:
            proposal = profile_setup.discover()
        except NetworkProfileSetupError as exc:
            raise HTTPException(
                status_code=409,
                detail={"code": exc.code, "message": str(exc)},
            ) from exc
        return call(lambda: authorization.save_network_profile_proposal(proposal))

    @app.post("/api/v1/network-profiles/activate")
    def activate_network_profile(
        activation: NetworkProfileActivationRequest, request: Request
    ) -> dict[str, Any]:
        actor = principal(request)
        return call(
            lambda: authorization.activate_network_profile(
                activation.proposal_id,
                confirm_route=activation.confirm_route,
                resolver_mode=activation.resolver_mode,
                registered_source_ipv4=activation.registered_source_ipv4,
                registered_source_ipv6=activation.registered_source_ipv6,
                ipv6_mode=activation.ipv6_mode,
                actor_id=actor.principal_id,
            )
        )

    @app.get("/api/v1/network-profiles")
    def list_network_profiles() -> dict[str, Any]:
        return {"profiles": authorization.list_network_profiles(), "execution_enabled": False}

    @app.post("/api/v1/network-profiles/{profile_id}/revoke")
    def revoke_network_profile(
        profile_id: str, revocation: NetworkProfileRevocationRequest, request: Request
    ) -> dict[str, Any]:
        actor = principal(request)
        return call(
            lambda: authorization.revoke_network_profile(
                profile_id, reason=revocation.reason, actor_id=actor.principal_id
            )
        )

    @app.post("/api/v1/shutdown")
    def shutdown() -> dict[str, str]:
        network_supervisor.stop()
        supervisor.stop()
        app.state.shutdown_requested.set()
        return {"status": "shutting_down"}

    @app.get("/api/v1/safety-state")
    def safety_state() -> dict[str, object]:
        return authorization.safety_state()

    @app.post("/api/v1/safety-state")
    def set_safety_state(change: SafetyRequest, request: Request) -> dict[str, Any]:
        actor = principal(request)
        return call(
            lambda: authorization.set_global_safety(
                status=change.status, reason=change.reason, actor_id=actor.principal_id
            )
        )

    @app.post("/api/v1/engagements/{engagement_id}/safety-state")
    def set_assessment_safety(
        engagement_id: str, change: SafetyRequest, request: Request
    ) -> dict[str, Any]:
        actor = principal(request)
        return call(
            lambda: authorization.set_assessment_safety(
                engagement_id,
                status=change.status,
                reason=change.reason,
                actor_id=actor.principal_id,
            )
        )

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
    def import_file_source(request: FileSourceRequest, http_request: Request) -> dict[str, Any]:
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

    @app.post("/api/v1/sources/urls")
    def import_url_source(request: UrlSourceRequest, http_request: Request) -> dict[str, Any]:
        actor = principal(http_request)

        def acquire_and_store() -> dict[str, Any]:
            try:
                acquired = UrlAcquirer().acquire(request.url)
            except AcquisitionError as exc:
                raise DomainError(exc.code, str(exc)) from exc
            return authorization.import_url_source(
                request.program_id,
                authority=request.authority,
                url=acquired.final_url,
                content=acquired.content,
                media_type=acquired.media_type,
                effective_at=request.effective_at,
                source_version=request.source_version,
                actor_id=actor.principal_id,
            )

        return call(acquire_and_store)

    @app.post("/api/v1/manifests")
    def save_manifest(request: ManifestRequest) -> dict[str, Any]:
        return call(lambda: authorization.save_manifest(request.engagement_id, request.document))

    @app.get("/api/v1/engagements/{engagement_id}/manifests")
    def list_manifests(engagement_id: str) -> dict[str, Any]:
        return {"manifests": call(lambda: authorization.list_manifests(engagement_id))}

    @app.get("/api/v1/engagements/{engagement_id}/manifests/diff")
    def diff_manifests(engagement_id: str, from_id: str, to_id: str) -> dict[str, Any]:
        return call(lambda: authorization.manifest_diff(engagement_id, from_id, to_id))

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

    @app.post("/api/v1/policies/{policy_id}/revoke")
    def revoke_policy(
        policy_id: str, revocation: RevocationRequest, request: Request
    ) -> dict[str, Any]:
        actor = principal(request)
        call(
            lambda: authorization.revoke_policy(
                policy_id, actor_id=actor.principal_id, reason=revocation.reason
            )
        )
        return {"id": policy_id, "status": "revoked"}

    @app.get("/api/v1/engagements/{engagement_id}/policies")
    def list_policies(engagement_id: str) -> dict[str, Any]:
        return {"policies": call(lambda: authorization.list_policies(engagement_id))}

    @app.post("/api/v1/policy-decisions")
    def evaluate_policy(evaluation: EvaluationRequest) -> dict[str, Any]:
        return call(
            lambda: authorization.evaluate_intent(evaluation.engagement_id, evaluation.intent)
        )

    @app.post("/api/v1/action-grants")
    def mint_action_grant(requested: GrantRequest) -> dict[str, Any]:
        return call(
            lambda: authorization.mint_action_grant(
                requested.decision_id, audience=requested.audience
            )
        )

    @app.post("/api/v1/action-grants/consume")
    def consume_action_grant(requested: GrantConsumptionRequest) -> dict[str, Any]:
        return call(
            lambda: authorization.consume_action_grant(
                requested.grant, requested.intent, audience=requested.audience
            )
        )

    @app.get("/api/v1/audit")
    def audit_events() -> dict[str, Any]:
        return call(
            lambda: {
                "events": authorization.audit_events(),
                "verification": authorization.verify_audit_chain(),
            }
        )

    @app.get("/api/v1/execution-traces/{result_id}")
    def execution_trace(result_id: str) -> dict[str, Any]:
        return call(lambda: authorization.execution_trace(result_id))

    @app.post("/api/v1/workflows")
    def create_workflow(
        requested: WorkflowCreateRequest, request: Request
    ) -> dict[str, Any]:
        actor = principal(request)
        return workflow_call(
            lambda: workflows.create(
                requested.engagement_id,
                idempotency_key=requested.idempotency_key,
                actor_id=actor.principal_id,
            )
        )

    @app.get("/api/v1/workflows/{workflow_id}")
    def get_workflow(workflow_id: str) -> dict[str, Any]:
        return workflow_call(lambda: workflows.get(workflow_id))

    @app.post("/api/v1/workflows/{workflow_id}/transition")
    def transition_workflow(
        workflow_id: str, requested: WorkflowTransitionRequest, request: Request
    ) -> dict[str, Any]:
        actor = principal(request)
        return workflow_call(
            lambda: workflows.transition(
                workflow_id,
                target_status=requested.target_status,
                expected_version=requested.expected_version,
                actor_type=actor.actor_type,
                actor_id=actor.principal_id,
            )
        )

    @app.post("/api/v1/workflows/{workflow_id}/tasks")
    def enqueue_workflow_task(
        workflow_id: str, requested: WorkflowTaskRequest, request: Request
    ) -> dict[str, Any]:
        actor = principal(request)
        return workflow_call(
            lambda: workflows.enqueue(
                workflow_id,
                task_kind=requested.task_kind,
                idempotency_key=requested.idempotency_key,
                input_refs=requested.input_refs,
                parent_task_id=requested.parent_task_id,
                actor_id=actor.principal_id,
            )
        )

    @app.post("/api/v1/workflow-tasks/{task_id}/cancel")
    def cancel_workflow_task(task_id: str, request: Request) -> dict[str, Any]:
        actor = principal(request)
        return workflow_call(
            lambda: workflows.cancel_task(task_id, actor_id=actor.principal_id)
        )

    @app.post("/api/v1/workflow-tasks/{task_id}/claim")
    def claim_workflow_task(
        task_id: str, requested: WorkflowTaskClaimRequest, request: Request
    ) -> dict[str, Any]:
        actor = principal(request)
        return workflow_call(
            lambda: workflows.claim_task(
                task_id,
                expected_version=requested.expected_version,
                lease_owner=actor.principal_id,
                lease_seconds=requested.lease_seconds,
            )
        )

    @app.post("/api/v1/workflow-tasks/{task_id}/heartbeat")
    def heartbeat_workflow_task(
        task_id: str, requested: WorkflowTaskLeaseRequest
    ) -> dict[str, Any]:
        return workflow_call(
            lambda: workflows.heartbeat_task(
                task_id,
                expected_version=requested.expected_version,
                lease_token=requested.lease_token,
                lease_seconds=requested.lease_seconds,
            )
        )

    @app.post("/api/v1/workflow-tasks/{task_id}/checkpoints")
    def checkpoint_workflow_task(
        task_id: str, requested: WorkflowTaskCheckpointRequest
    ) -> dict[str, Any]:
        return workflow_call(
            lambda: workflows.checkpoint_task(
                task_id,
                expected_version=requested.expected_version,
                lease_token=requested.lease_token,
                progress=requested.progress,
                output_refs=requested.output_refs,
            )
        )

    @app.post("/api/v1/workflow-tasks/{task_id}/finalize")
    def finalize_workflow_task(
        task_id: str, requested: WorkflowTaskFinalizeRequest
    ) -> dict[str, Any]:
        return workflow_call(
            lambda: workflows.finalize_task(
                task_id,
                operation=requested.operation,
                expected_version=requested.expected_version,
                lease_token=requested.lease_token,
                idempotency_key=requested.idempotency_key,
                error_code=requested.error_code,
                retry_delay_seconds=requested.retry_delay_seconds,
            )
        )

    return app
