from __future__ import annotations

import secrets
import sqlite3
import threading
from base64 import b64decode
from binascii import Error as Base64Error
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from pentai_core import __version__
from pentai_core.ai_provider_configuration_snapshot import (
    ProviderConfigurationSnapshotError,
    ProviderConfigurationSnapshotService,
)
from pentai_core.ai_provider_registry_activation import (
    ProviderRegistryActivationError,
    ProviderRegistryActivationService,
)
from pentai_core.ai_provider_registry_snapshot import (
    ProviderRegistrySnapshotError,
    ProviderRegistrySnapshotService,
)
from pentai_core.authorization import AuthorizationService, DomainError
from pentai_core.backup import BackupError, BackupService
from pentai_core.config import Settings, allowed_origins
from pentai_core.controlled_dns_composition import compose_controlled_resolver_provider
from pentai_core.coverage import AssessmentCoverageService, CoverageError
from pentai_core.database import register_storage_failure_handler
from pentai_core.evidence import EvidenceError, EvidenceService
from pentai_core.evidence_store import EncryptedEvidenceStore
from pentai_core.findings import FindingError, FindingService
from pentai_core.gateway_runtime_composition import compose_gateway_runtime_supervisor
from pentai_core.gateway_runtime_supervisor import RuntimeSupervisorControl
from pentai_core.local_model_intent import LocalModelIntentError, LocalModelIntentService
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
from pentai_core.no_findings_reports import NoFindingsReportError, NoFindingsReportService
from pentai_core.orchestration_approval import (
    OrchestrationApprovalError,
    OrchestrationApprovalService,
)
from pentai_core.policy_signing import PolicySigner
from pentai_core.report_approvals import ReportApprovalError, ReportApprovalService
from pentai_core.report_exports import ReportExportError, ReportExportService
from pentai_core.reports import ReportError, ReportService
from pentai_core.source_store import EncryptedSourceStore
from pentai_core.storage_safety import StorageSafetyLatch
from pentai_core.url_acquisition import AcquisitionError, UrlAcquirer
from pentai_core.worker_containment_supervisor import WorkerSupervisorControl
from pentai_core.worker_runtime_composition import compose_worker_runtime_supervisor
from pentai_core.workflow import AssessmentWorkflowService, WorkflowError


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    execution_enabled: bool


@dataclass(frozen=True)
class LocalPrincipal:
    principal_id: str
    session_id: str
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


class LocalModelEvaluationRequest(StrictRequest):
    intent_id: UUID


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


class EvidenceOriginalRequest(StrictRequest):
    evidence_kind: str
    media_type: str
    classification: str = "restricted"
    idempotency_key: str = Field(min_length=16, max_length=128)
    content_base64: str = Field(max_length=2_796_204)
    execution_trace_id: str | None = None


class EvidenceRedactionSpan(StrictRequest):
    start: int = Field(ge=0)
    end: int = Field(ge=1)
    reason: str


class EvidenceRedactionRequest(StrictRequest):
    redactions: list[EvidenceRedactionSpan] = Field(min_length=1, max_length=256)
    classification: str
    confirm_classification: bool
    idempotency_key: str = Field(min_length=16, max_length=128)


class EvidenceDeletionRequest(StrictRequest):
    artifact_type: str
    artifact_id: str
    expected_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    reason: str = Field(min_length=1, max_length=500)
    confirm_permanent_deletion: bool


class BackupCreateRequest(StrictRequest):
    confirm_backup: bool


class BackupRestoreDrillRequest(StrictRequest):
    confirm_restore_drill: bool


class BackupRotationRequest(StrictRequest):
    retain_count: int = Field(ge=2, le=20)


class BackupPurgeRequest(StrictRequest):
    expected_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    reason: str = Field(min_length=1, max_length=500)
    confirm_permanent_deletion: bool


class FindingCreateRequest(StrictRequest):
    idempotency_key: str = Field(min_length=16, max_length=128)
    title: str = Field(min_length=1, max_length=200)
    severity: str
    cvss_vector: str
    cvss_score: float = Field(ge=0, le=10)
    cwe: str
    confidence: int = Field(ge=0, le=100)
    affected_asset_rule_ids: list[str] = Field(min_length=1, max_length=64)
    evidence_ids: list[str] = Field(min_length=1, max_length=128)
    reproduction: str = Field(min_length=1, max_length=20_000)
    impact: str = Field(min_length=1, max_length=10_000)
    remediation: str = Field(min_length=1, max_length=10_000)
    references: list[str] = Field(default_factory=list, max_length=32)


class FindingTransitionRequest(StrictRequest):
    target_state: str
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=1000)
    validation_status: str | None = None
    duplicate_status: str | None = None
    duplicate_of: str | None = None


class ReportDraftRequest(StrictRequest):
    idempotency_key: str = Field(min_length=16, max_length=128)
    title: str = Field(min_length=1, max_length=200)
    template: str = "generic"
    finding_ids: list[str] = Field(min_length=1, max_length=100)


class CoverageRecordRequest(StrictRequest):
    idempotency_key: str = Field(min_length=16, max_length=128)
    asset_rule_id: str
    capability_rule_id: str
    capability: str = Field(min_length=2, max_length=128)
    outcome: str
    started_at: datetime
    ended_at: datetime
    evidence_ids: list[str] = Field(default_factory=list, max_length=128)
    limitations: list[str] = Field(min_length=1, max_length=32)
    notes: str = Field(min_length=1, max_length=5000)


class NoFindingsReportDraftRequest(StrictRequest):
    idempotency_key: str = Field(min_length=16, max_length=128)
    title: str = Field(min_length=1, max_length=200)
    template: str = "generic"
    coverage_ids: list[str] = Field(min_length=1, max_length=500)


class ReportExportApprovalRequest(StrictRequest):
    report_kind: str
    expected_status: str
    reason: str = Field(min_length=1, max_length=1000)
    confirm_export_ready: bool


class OrchestrationApprovalCreateRequest(StrictRequest):
    assessment_id: str
    expected_plan_revision: int = Field(ge=1)
    expected_task_revision: int = Field(ge=1)
    policy_bundle_id: str
    policy_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class OrchestrationApprovalDecisionRequest(StrictRequest):
    decision: str
    reason: str = Field(min_length=1, max_length=1000)
    explicit_confirmation: bool


class OrchestrationApprovalConsumptionRequest(StrictRequest):
    consumption_id: str
    decision_id: str
    request_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    decision_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    expected_plan_revision: int = Field(ge=1)
    expected_task_revision: int = Field(ge=1)


class ProviderRegistrySnapshotRequest(StrictRequest):
    command_id: str = Field(min_length=36, max_length=36)
    requested_at: str = Field(min_length=20, max_length=40)
    expires_at: str = Field(min_length=20, max_length=40)
    registry: dict[str, Any]


class ProviderRegistryActivationRequest(StrictRequest):
    command_id: str = Field(min_length=36, max_length=36)
    requested_at: str = Field(min_length=20, max_length=40)
    expires_at: str = Field(min_length=20, max_length=40)


class ProviderConfigurationSnapshotRequest(StrictRequest):
    command_id: str = Field(min_length=36, max_length=36)
    requested_at: str = Field(min_length=20, max_length=40)
    expires_at: str = Field(min_length=20, max_length=40)
    configuration: dict[str, Any]
    secret_reference: dict[str, Any] | None = None


class ReportFileExportRequest(StrictRequest):
    report_kind: str
    format: str
    destination_directory: str = Field(min_length=1, max_length=4096)
    confirm_restricted_export: bool


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


def evidence_call[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except EvidenceError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


def backup_call[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except BackupError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


def finding_call[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except FindingError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


def report_call[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except ReportError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


def coverage_call[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except CoverageError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


def no_findings_report_call[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except NoFindingsReportError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


def report_approval_call[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except ReportApprovalError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


def orchestration_approval_call[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except OrchestrationApprovalError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


def provider_registry_snapshot_call[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except ProviderRegistrySnapshotError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


def provider_registry_activation_call[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except ProviderRegistryActivationError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


def provider_configuration_snapshot_call[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except ProviderConfigurationSnapshotError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


def local_model_intent_call[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except LocalModelIntentError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


def report_export_call[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except ReportExportError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


def _decode_file_content(encoded: str) -> bytes:
    try:
        return b64decode(encoded, validate=True)
    except (Base64Error, ValueError) as exc:
        raise DomainError("SOURCE_ENCODING_INVALID", "file content encoding is invalid") from exc


def _decode_evidence_content(encoded: str) -> bytes:
    try:
        return b64decode(encoded, validate=True)
    except (Base64Error, ValueError) as exc:
        raise EvidenceError(
            "EVIDENCE_ENCODING_INVALID", "evidence content encoding is invalid"
        ) from exc


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
    worker_runtime_supervisor: WorkerSupervisorControl | None = None,
    network_profile_setup_service: NetworkProfileSetupService | None = None,
) -> FastAPI:
    runtime = settings or Settings.from_environment()
    runtime.validate()
    migrate(runtime.database_path)
    storage_safety = StorageSafetyLatch()
    source_store = (
        EncryptedSourceStore(
            runtime.source_store_path,
            runtime.source_master_key,
            failure_handler=storage_safety.trip,
        )
        if runtime.source_master_key is not None
        else None
    )
    signer = PolicySigner(runtime.policy_signing_key) if runtime.policy_signing_key else None
    authorization = AuthorizationService(
        runtime.database_path,
        source_store=source_store,
        policy_signer=signer,
        storage_safety=storage_safety,
    )
    register_storage_failure_handler(runtime.database_path, storage_safety.trip)

    def stop_for_evidence_failure() -> None:
        storage_safety.trip()
        try:
            authorization.set_global_safety(
                status="stopped",
                reason="evidence storage failure requires human recovery",
                actor_id="evidence-service",
            )
        except (DomainError, sqlite3.Error):
            # The in-memory latch remains authoritative when storage cannot record the stop.
            pass

    evidence_store = (
        EncryptedEvidenceStore(
            runtime.source_store_path.parent / "evidence-blobs",
            runtime.source_master_key,
            failure_handler=storage_safety.trip,
        )
        if runtime.source_master_key is not None
        else None
    )
    evidence = EvidenceService(
        runtime.database_path,
        evidence_store,
        storage_failure_handler=stop_for_evidence_failure,
    )
    findings = FindingService(runtime.database_path)
    reports = ReportService(runtime.database_path)
    coverage = AssessmentCoverageService(runtime.database_path)
    no_findings_reports = NoFindingsReportService(runtime.database_path)
    report_approvals = ReportApprovalService(runtime.database_path)
    orchestration_approvals = OrchestrationApprovalService(authorization)
    provider_registry_snapshots = ProviderRegistrySnapshotService(authorization)
    provider_registry_activations = ProviderRegistryActivationService(authorization)
    provider_configuration_snapshots = ProviderConfigurationSnapshotService(authorization)
    local_model_intents = LocalModelIntentService(authorization)
    report_exports = ReportExportService(runtime.database_path)
    backups = BackupService(
        runtime.database_path,
        evidence_store,
        runtime.source_master_key,
        source_store=source_store,
        storage_failure_handler=storage_safety.trip,
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
    evidence.recover_deletions()
    worker_supervisor = worker_runtime_supervisor or compose_worker_runtime_supervisor(
        settings=runtime, safety_control=authorization
    )
    worker_supervisor.start()
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
    app.state.worker_runtime_supervisor = worker_supervisor
    app.state.network_safety_supervisor = network_supervisor
    app.state.controlled_resolver_provider = controlled_resolver_provider
    app.state.network_profile_setup_service = profile_setup
    app.state.assessment_workflows = workflows
    app.state.provider_registry_snapshots = provider_registry_snapshots
    app.state.provider_registry_activations = provider_registry_activations
    app.state.evidence = evidence
    app.state.findings = findings
    app.state.reports = reports
    app.state.backups = backups
    app.state.storage_safety = storage_safety
    local_session_id = str(uuid4())
    app.router.add_event_handler("shutdown", network_supervisor.stop)
    app.router.add_event_handler("shutdown", supervisor.stop)
    app.router.add_event_handler("shutdown", worker_supervisor.stop)
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
            request.state.principal = LocalPrincipal("test-session", local_session_id)
            return await call_next(request)
        authorization_header = request.headers.get("authorization", "")
        prefix = "Bearer "
        if not authorization_header.startswith(prefix):
            return _unauthorized()
        supplied = authorization_header[len(prefix) :]
        expected = runtime.launch_credential or ""
        if not supplied or not secrets.compare_digest(supplied, expected):
            return _unauthorized()
        request.state.principal = LocalPrincipal("local-desktop-session", local_session_id)
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
        worker_status = worker_supervisor.status()
        return HealthResponse(
            status=(
                "degraded"
                if storage_safety.reason_code() is not None
                or "degraded"
                in {
                    runtime_status["status"],
                    network_status["status"],
                    worker_status["status"],
                }
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
        worker_status = worker_supervisor.status()
        if storage_safety.reason_code() is not None:
            return JSONResponse(
                status_code=503,
                content={
                    "status": "degraded",
                    "reason_code": storage_safety.reason_code(),
                    "execution_enabled": False,
                },
            )
        if "degraded" in {
            runtime_status["status"],
            network_status["status"],
            worker_status["status"],
        }:
            reason_code = (
                runtime_status["reason_code"]
                if runtime_status["status"] == "degraded"
                else (
                    network_status["reason_code"]
                    if network_status["status"] == "degraded"
                    else worker_status["reason_code"]
                )
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

    @app.get("/api/v1/worker-runtime-supervision")
    def worker_runtime_supervision() -> dict[str, object]:
        return worker_supervisor.status()

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
        worker_supervisor.stop()
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

    @app.get("/api/v1/programs/{program_id}/engagements")
    def list_engagements(program_id: str) -> dict[str, Any]:
        return {"engagements": call(lambda: authorization.list_engagements(program_id))}

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

    @app.get("/api/v1/engagements/{engagement_id}/policies/{policy_id}")
    def get_policy(engagement_id: str, policy_id: str) -> dict[str, Any]:
        return call(lambda: authorization.get_policy(engagement_id, policy_id))

    @app.post("/api/v1/policy-decisions")
    def evaluate_policy(evaluation: EvaluationRequest) -> dict[str, Any]:
        return call(
            lambda: authorization.evaluate_intent(evaluation.engagement_id, evaluation.intent)
        )

    @app.post("/api/v1/local-model-policy-decisions")
    def evaluate_local_model_policy(
        evaluation: LocalModelEvaluationRequest,
    ) -> dict[str, Any]:
        return local_model_intent_call(
            lambda: local_model_intents.evaluate(str(evaluation.intent_id))
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

    @app.post("/api/v1/workflows/{workflow_id}/evidence/originals")
    def create_evidence_original(
        workflow_id: str, requested: EvidenceOriginalRequest, request: Request
    ) -> dict[str, Any]:
        actor = principal(request)
        return evidence_call(
            lambda: evidence.create_original(
                workflow_id,
                content=_decode_evidence_content(requested.content_base64),
                evidence_kind=requested.evidence_kind,
                media_type=requested.media_type,
                classification=requested.classification,
                idempotency_key=requested.idempotency_key,
                actor_id=actor.principal_id,
                execution_trace_id=requested.execution_trace_id,
            )
        )

    @app.get("/api/v1/evidence/{evidence_id}/metadata")
    def evidence_metadata(evidence_id: str, request: Request) -> dict[str, Any]:
        actor = principal(request)
        return evidence_call(lambda: evidence.metadata(evidence_id, actor_id=actor.principal_id))

    @app.post("/api/v1/evidence/{evidence_id}/redactions")
    def create_evidence_redaction(
        evidence_id: str, requested: EvidenceRedactionRequest, request: Request
    ) -> dict[str, Any]:
        actor = principal(request)
        return evidence_call(
            lambda: evidence.create_redaction(
                evidence_id,
                redactions=[span.model_dump() for span in requested.redactions],
                classification=requested.classification,
                confirm_classification=requested.confirm_classification,
                idempotency_key=requested.idempotency_key,
                actor_id=actor.principal_id,
            )
        )

    @app.get("/api/v1/evidence/derivatives/{derivative_id}/preview")
    def evidence_redaction_preview(derivative_id: str, request: Request) -> dict[str, Any]:
        actor = principal(request)
        return evidence_call(
            lambda: evidence.preview_redaction(derivative_id, actor_id=actor.principal_id)
        )

    @app.post("/api/v1/evidence/deletions")
    def delete_evidence(requested: EvidenceDeletionRequest, request: Request) -> dict[str, Any]:
        actor = principal(request)
        return evidence_call(
            lambda: evidence.delete_artifact(
                requested.artifact_type,
                requested.artifact_id,
                expected_sha256=requested.expected_sha256,
                reason=requested.reason,
                confirm_permanent_deletion=requested.confirm_permanent_deletion,
                actor_id=actor.principal_id,
            )
        )

    @app.post("/api/v1/workflows/{workflow_id}/findings")
    def create_finding(
        workflow_id: str, requested: FindingCreateRequest, request: Request
    ) -> dict[str, Any]:
        actor = principal(request)
        return finding_call(
            lambda: findings.create(
                workflow_id,
                idempotency_key=requested.idempotency_key,
                title=requested.title,
                severity=requested.severity,
                cvss_vector=requested.cvss_vector,
                cvss_score=requested.cvss_score,
                cwe=requested.cwe,
                confidence=requested.confidence,
                affected_asset_rule_ids=requested.affected_asset_rule_ids,
                evidence_ids=requested.evidence_ids,
                reproduction=requested.reproduction,
                impact=requested.impact,
                remediation=requested.remediation,
                references=requested.references,
                actor_id=actor.principal_id,
            )
        )

    @app.get("/api/v1/workflows/{workflow_id}/findings")
    def list_findings(workflow_id: str) -> dict[str, Any]:
        return {"findings": finding_call(lambda: findings.list_for_workflow(workflow_id))}

    @app.get("/api/v1/findings/{finding_id}")
    def get_finding(finding_id: str) -> dict[str, Any]:
        return finding_call(lambda: findings.get(finding_id))

    @app.get("/api/v1/findings/{finding_id}/history")
    def finding_history(finding_id: str) -> dict[str, Any]:
        return {"versions": finding_call(lambda: findings.history(finding_id))}

    @app.post("/api/v1/findings/{finding_id}/transition")
    def transition_finding(
        finding_id: str, requested: FindingTransitionRequest, request: Request
    ) -> dict[str, Any]:
        actor = principal(request)
        return finding_call(
            lambda: findings.transition(
                finding_id,
                target_state=requested.target_state,
                expected_version=requested.expected_version,
                reason=requested.reason,
                validation_status=requested.validation_status,
                duplicate_status=requested.duplicate_status,
                duplicate_of=requested.duplicate_of,
                actor_id=actor.principal_id,
            )
        )

    @app.post("/api/v1/workflows/{workflow_id}/report-drafts")
    def create_report_draft(
        workflow_id: str, requested: ReportDraftRequest, request: Request
    ) -> dict[str, Any]:
        actor = principal(request)
        return report_call(
            lambda: reports.create_draft(
                workflow_id,
                idempotency_key=requested.idempotency_key,
                title=requested.title,
                template=requested.template,
                finding_ids=requested.finding_ids,
                actor_id=actor.principal_id,
            )
        )

    @app.post("/api/v1/workflows/{workflow_id}/coverage")
    def record_assessment_coverage(
        workflow_id: str, requested: CoverageRecordRequest, request: Request
    ) -> dict[str, Any]:
        actor = principal(request)
        return coverage_call(
            lambda: coverage.record(
                workflow_id,
                idempotency_key=requested.idempotency_key,
                asset_rule_id=requested.asset_rule_id,
                capability_rule_id=requested.capability_rule_id,
                capability=requested.capability,
                outcome=requested.outcome,
                started_at=requested.started_at,
                ended_at=requested.ended_at,
                evidence_ids=requested.evidence_ids,
                limitations=requested.limitations,
                notes=requested.notes,
                actor_id=actor.principal_id,
            )
        )

    @app.get("/api/v1/workflows/{workflow_id}/coverage")
    def list_assessment_coverage(workflow_id: str) -> dict[str, Any]:
        return {"coverage": coverage_call(lambda: coverage.list_for_workflow(workflow_id))}

    @app.post("/api/v1/workflows/{workflow_id}/no-findings-report-drafts")
    def create_no_findings_report_draft(
        workflow_id: str, requested: NoFindingsReportDraftRequest, request: Request
    ) -> dict[str, Any]:
        actor = principal(request)
        return no_findings_report_call(
            lambda: no_findings_reports.create_draft(
                workflow_id,
                idempotency_key=requested.idempotency_key,
                title=requested.title,
                template=requested.template,
                coverage_ids=requested.coverage_ids,
                actor_id=actor.principal_id,
            )
        )

    @app.get("/api/v1/no-findings-report-drafts/{report_id}")
    def get_no_findings_report_draft(report_id: str) -> dict[str, Any]:
        return no_findings_report_call(lambda: no_findings_reports.get(report_id))

    @app.get("/api/v1/no-findings-report-drafts/{report_id}/artifacts/{format_name}")
    def get_no_findings_report_artifact(report_id: str, format_name: str) -> Response:
        media_type, content, digest = no_findings_report_call(
            lambda: no_findings_reports.artifact(report_id, format_name)
        )
        return Response(
            content=content,
            media_type=media_type,
            headers={
                "X-Content-SHA256": digest,
                "X-PentAI-Report-Status": "draft",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'none'; sandbox",
            },
        )

    @app.post("/api/v1/report-drafts/{report_id}/export-approval")
    def approve_report_export(
        report_id: str, requested: ReportExportApprovalRequest, request: Request
    ) -> dict[str, Any]:
        actor = principal(request)
        return report_approval_call(
            lambda: report_approvals.approve(
                report_id,
                report_kind=requested.report_kind,
                expected_status=requested.expected_status,
                reason=requested.reason,
                confirm_export_ready=requested.confirm_export_ready,
                actor_id=actor.principal_id,
            )
        )

    @app.post("/api/v1/orchestration/plans/{plan_id}/tasks/{task_id}/approval-request")
    def create_orchestration_task_approval_request(
        plan_id: str,
        task_id: str,
        requested: OrchestrationApprovalCreateRequest,
        request: Request,
    ) -> dict[str, Any]:
        actor = principal(request)
        return orchestration_approval_call(
            lambda: orchestration_approvals.create_request(
                assessment_id=requested.assessment_id,
                plan_id=plan_id,
                expected_plan_revision=requested.expected_plan_revision,
                task_id=task_id,
                expected_task_revision=requested.expected_task_revision,
                policy_bundle_id=requested.policy_bundle_id,
                policy_hash=requested.policy_hash,
                authenticated_actor_id=actor.principal_id,
                authenticated_session_id=actor.session_id,
            )
        )

    @app.post("/api/v1/orchestration/task-approval-requests/{request_id}/decision")
    def decide_orchestration_task_approval(
        request_id: str,
        requested: OrchestrationApprovalDecisionRequest,
        request: Request,
    ) -> dict[str, Any]:
        actor = principal(request)
        return orchestration_approval_call(
            lambda: orchestration_approvals.decide(
                request_id,
                decision=requested.decision,
                reason=requested.reason,
                explicit_confirmation=requested.explicit_confirmation,
                approver_id=actor.principal_id,
                authenticated_session=True,
                authenticated_session_id=actor.session_id,
            )
        )

    @app.post("/api/v1/orchestration/task-approval-requests/{request_id}/consume")
    def consume_orchestration_task_approval(
        request_id: str,
        requested: OrchestrationApprovalConsumptionRequest,
        request: Request,
    ) -> dict[str, Any]:
        actor = principal(request)
        return orchestration_approval_call(
            lambda: orchestration_approvals.consume(
                request_id,
                consumption_id=requested.consumption_id,
                decision_id=requested.decision_id,
                request_digest=requested.request_digest,
                decision_digest=requested.decision_digest,
                expected_plan_revision=requested.expected_plan_revision,
                expected_task_revision=requested.expected_task_revision,
                authenticated_actor_id=actor.principal_id,
                authenticated_session_id=actor.session_id,
            )
        )

    @app.post("/api/v1/ai/provider-registry-snapshots")
    def create_provider_registry_snapshot(
        requested: ProviderRegistrySnapshotRequest, request: Request
    ) -> dict[str, Any]:
        actor = principal(request)
        return provider_registry_snapshot_call(
            lambda: provider_registry_snapshots.produce(
                requested.registry,
                command_id=requested.command_id,
                requested_at=requested.requested_at,
                expires_at=requested.expires_at,
                authenticated_actor_id=actor.principal_id,
                authenticated_session_id=actor.session_id,
            )
        )

    @app.post("/api/v1/ai/provider-registry-snapshots/{snapshot_id}/activate")
    def activate_provider_registry_snapshot(
        snapshot_id: str,
        requested: ProviderRegistryActivationRequest,
        request: Request,
    ) -> dict[str, Any]:
        actor = principal(request)
        return provider_registry_activation_call(
            lambda: provider_registry_activations.activate(
                snapshot_id,
                command_id=requested.command_id,
                requested_at=requested.requested_at,
                expires_at=requested.expires_at,
                authenticated_actor_id=actor.principal_id,
                authenticated_session_id=actor.session_id,
            )
        )

    @app.post(
        "/api/v1/ai/provider-registry-activations/{activation_id}/configuration-snapshots"
    )
    def create_provider_configuration_snapshot(
        activation_id: str,
        requested: ProviderConfigurationSnapshotRequest,
        request: Request,
    ) -> dict[str, Any]:
        actor = principal(request)
        return provider_configuration_snapshot_call(
            lambda: provider_configuration_snapshots.produce(
                activation_id,
                requested.configuration,
                secret_reference=requested.secret_reference,
                command_id=requested.command_id,
                requested_at=requested.requested_at,
                expires_at=requested.expires_at,
                authenticated_actor_id=actor.principal_id,
                authenticated_session_id=actor.session_id,
            )
        )

    @app.get("/api/v1/report-drafts/{report_id}/export-approval")
    def get_report_export_approval(report_id: str, report_kind: str) -> dict[str, Any]:
        return report_approval_call(
            lambda: report_approvals.get(report_id, report_kind=report_kind)
        )

    @app.post("/api/v1/report-drafts/{report_id}/file-exports")
    def export_report_file(
        report_id: str, requested: ReportFileExportRequest, request: Request
    ) -> dict[str, Any]:
        actor = principal(request)
        return report_export_call(
            lambda: report_exports.export(
                report_id,
                report_kind=requested.report_kind,
                format_name=requested.format,
                destination_directory=Path(requested.destination_directory),
                confirm_restricted_export=requested.confirm_restricted_export,
                actor_id=actor.principal_id,
            )
        )

    @app.get("/api/v1/report-drafts/{report_id}")
    def get_report_draft(report_id: str) -> dict[str, Any]:
        return report_call(lambda: reports.get(report_id))

    @app.get("/api/v1/report-drafts/{report_id}/artifacts/{format_name}")
    def get_report_artifact(report_id: str, format_name: str) -> Response:
        media_type, content, digest = report_call(
            lambda: reports.artifact(report_id, format_name)
        )
        return Response(
            content=content,
            media_type=media_type,
            headers={
                "X-Content-SHA256": digest,
                "X-PentAI-Report-Status": "draft",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'none'; sandbox",
            },
        )

    @app.post("/api/v1/backups")
    def create_backup(requested: BackupCreateRequest, request: Request) -> dict[str, object]:
        actor = principal(request)
        if requested.confirm_backup is not True:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "BACKUP_CONFIRMATION_REQUIRED",
                    "message": "encrypted backup requires explicit human confirmation",
                },
            )
        backup_id = str(uuid4())
        destination = runtime.backup_store_path / f"{backup_id}.pentai-backup"
        return backup_call(
            lambda: backups.create(destination, actor_id=actor.principal_id, backup_id=backup_id)
        )

    @app.get("/api/v1/backups/inventory")
    def backup_inventory(request: Request) -> dict[str, object]:
        actor = principal(request)
        return backup_call(
            lambda: backups.inventory(runtime.backup_store_path, actor_id=actor.principal_id)
        )

    @app.post("/api/v1/backups/rotation-plan")
    def backup_rotation_plan(
        requested: BackupRotationRequest, request: Request
    ) -> dict[str, object]:
        actor = principal(request)
        return backup_call(
            lambda: backups.rotation_plan(
                runtime.backup_store_path,
                retain_count=requested.retain_count,
                actor_id=actor.principal_id,
            )
        )

    @app.post("/api/v1/backups/{backup_id}/purge")
    def purge_backup(
        backup_id: str, requested: BackupPurgeRequest, request: Request
    ) -> dict[str, object]:
        actor = principal(request)
        return backup_call(
            lambda: backups.purge(
                runtime.backup_store_path,
                backup_id,
                expected_sha256=requested.expected_sha256,
                reason=requested.reason,
                confirm_permanent_deletion=requested.confirm_permanent_deletion,
                actor_id=actor.principal_id,
            )
        )

    @app.post("/api/v1/backups/{backup_id}/restore-drill")
    def restore_backup_drill(
        backup_id: str, requested: BackupRestoreDrillRequest, request: Request
    ) -> dict[str, object]:
        actor = principal(request)
        if requested.confirm_restore_drill is not True:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "RESTORE_CONFIRMATION_REQUIRED",
                    "message": "restore drill requires explicit human confirmation",
                },
            )
        try:
            normalized_id = str(UUID(backup_id))
        except ValueError as exc:
            raise HTTPException(
                status_code=409,
                detail={"code": "BACKUP_ID_INVALID", "message": "backup id is invalid"},
            ) from exc
        backup = runtime.backup_store_path / f"{normalized_id}.pentai-backup"
        destination = runtime.backup_store_path / "restore-drills" / normalized_id
        return backup_call(
            lambda: backups.restore_drill(backup, destination, actor_id=actor.principal_id)
        )

    @app.post("/api/v1/workflows")
    def create_workflow(requested: WorkflowCreateRequest, request: Request) -> dict[str, Any]:
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
        return workflow_call(lambda: workflows.cancel_task(task_id, actor_id=actor.principal_id))

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
