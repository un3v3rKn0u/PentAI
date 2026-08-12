from __future__ import annotations

import html
import json
import re
import sqlite3
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

from pentai_policy import canonical_json, content_hash
from pentai_policy.document import contract_issues

from pentai_core.audit import append_audit_event
from pentai_core.database import transaction

_TEMPLATES = {"generic", "hackerone", "bugcrowd", "intigriti"}
_FORMATS = {
    "markdown": "text/markdown; charset=utf-8",
    "html": "text/html; charset=utf-8",
    "json": "application/json",
    "pdf": "application/pdf",
}


class ReportError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ReportService:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def create_draft(
        self,
        workflow_id: str,
        *,
        idempotency_key: str,
        title: str,
        template: str,
        finding_ids: list[str],
        actor_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        created_at = _timestamp(now)
        _identity(workflow_id, "REPORT_WORKFLOW_INVALID")
        if not 1 <= len(actor_id) <= 128:
            raise ReportError("REPORT_ACTOR_INVALID", "report actor is invalid")
        if not 16 <= len(idempotency_key) <= 128 or not re.fullmatch(
            r"[A-Za-z0-9_.:-]+", idempotency_key
        ):
            raise ReportError("REPORT_IDEMPOTENCY_INVALID", "report idempotency is invalid")
        title = title.strip()
        if not 1 <= len(title) <= 200 or template not in _TEMPLATES:
            raise ReportError("REPORT_REQUEST_INVALID", "report request is invalid")
        if not 1 <= len(finding_ids) <= 100 or len(set(finding_ids)) != len(finding_ids):
            raise ReportError("REPORT_FINDINGS_INVALID", "report findings are invalid")
        for finding_id in finding_ids:
            _identity(finding_id, "REPORT_FINDINGS_INVALID")

        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """SELECT document_json FROM report_drafts
                   WHERE workflow_id = ? AND idempotency_key = ?""",
                (workflow_id, idempotency_key),
            ).fetchone()
            if existing is not None:
                document = cast(dict[str, Any], json.loads(existing["document_json"]))
                if document["title"] != title or document["template"] != template or [
                    item["finding_id"] for item in document["finding_refs"]
                ] != finding_ids:
                    raise ReportError(
                        "REPORT_IDEMPOTENCY_CONFLICT", "report idempotency key was reused"
                    )
                return document
            workflow = connection.execute(
                "SELECT * FROM assessment_workflows WHERE workflow_id = ?", (workflow_id,)
            ).fetchone()
            if workflow is None:
                raise ReportError("REPORT_WORKFLOW_MISSING", "report workflow is missing")
            findings = []
            refs = []
            for finding_id in finding_ids:
                row = connection.execute(
                    "SELECT * FROM findings WHERE finding_id = ? AND workflow_id = ?",
                    (finding_id, workflow_id),
                ).fetchone()
                if row is None or row["state"] != "report_ready":
                    raise ReportError("REPORT_FINDING_NOT_READY", "report finding is not ready")
                finding = json.loads(row["document_json"])
                findings.append(finding)
                refs.append(
                    {
                        "finding_id": finding_id,
                        "version": row["version"],
                        "content_hash": row["content_hash"],
                    }
                )
            report_id = str(uuid4())
            payload = _report_payload(
                title, template, workflow, findings, str(workflow["policy_bundle_id"])
            )
            rendered = _render(payload)
            artifacts: list[dict[str, Any]] = [
                {
                    "format": format_name,
                    "media_type": _FORMATS[format_name],
                    "sha256": sha256(content).hexdigest(),
                    "size_bytes": len(content),
                }
                for format_name, content in rendered.items()
            ]
            if any(item["size_bytes"] > 2_097_152 for item in artifacts):
                raise ReportError("REPORT_TOO_LARGE", "report draft exceeds its output bound")
            document = {
                "schema_version": "1.0.0",
                "report_id": report_id,
                "workflow_id": workflow_id,
                "engagement_id": workflow["engagement_id"],
                "policy_bundle_id": workflow["policy_bundle_id"],
                "status": "draft",
                "classification": "restricted",
                "template": template,
                "title": title,
                "finding_refs": refs,
                "artifacts": artifacts,
                "created_by": actor_id,
                "created_at": created_at,
            }
            issues = contract_issues(document, "report-draft-v1.schema.json")
            if issues:
                raise ReportError(
                    "REPORT_CONTRACT_INVALID", "; ".join(str(issue) for issue in issues)
                )
            connection.execute(
                """INSERT INTO report_drafts(
                    report_id, workflow_id, engagement_id, policy_bundle_id,
                    idempotency_key, template, title, finding_refs_json,
                    document_json, content_hash, created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    report_id, workflow_id, workflow["engagement_id"],
                    workflow["policy_bundle_id"], idempotency_key, template, title,
                    canonical_json(refs), canonical_json(document), content_hash(document),
                    actor_id, created_at,
                ),
            )
            for descriptor in artifacts:
                content = rendered[descriptor["format"]]
                connection.execute(
                    """INSERT INTO report_draft_artifacts(
                        report_id, format, media_type, content, sha256, size_bytes
                    ) VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        report_id, descriptor["format"], descriptor["media_type"],
                        content, descriptor["sha256"], descriptor["size_bytes"],
                    ),
                )
            append_audit_event(
                connection,
                action="report.draft_created",
                subject_type="report",
                subject_id=report_id,
                actor_type="human",
                actor_id=actor_id,
                data={
                    "workflow_id": workflow_id,
                    "policy_bundle_id": workflow["policy_bundle_id"],
                    "finding_refs": refs,
                    "artifact_digests": {
                        item["format"]: item["sha256"] for item in artifacts
                    },
                    "status": "draft",
                },
                occurred_at=created_at,
            )
        return document

    def get(self, report_id: str) -> dict[str, Any]:
        _identity(report_id, "REPORT_ID_INVALID")
        with transaction(self.database_path) as connection:
            row = connection.execute(
                "SELECT document_json FROM report_drafts WHERE report_id = ?", (report_id,)
            ).fetchone()
        if row is None:
            raise ReportError("REPORT_NOT_FOUND", "report draft does not exist")
        return cast(dict[str, Any], json.loads(row["document_json"]))

    def artifact(self, report_id: str, format_name: str) -> tuple[str, bytes, str]:
        _identity(report_id, "REPORT_ID_INVALID")
        if format_name not in _FORMATS:
            raise ReportError("REPORT_FORMAT_INVALID", "report format is invalid")
        with transaction(self.database_path) as connection:
            row = connection.execute(
                """SELECT media_type, content, sha256 FROM report_draft_artifacts
                   WHERE report_id = ? AND format = ?""",
                (report_id, format_name),
            ).fetchone()
        if row is None:
            raise ReportError("REPORT_NOT_FOUND", "report artifact does not exist")
        content = bytes(row["content"])
        if sha256(content).hexdigest() != row["sha256"]:
            raise ReportError("REPORT_INTEGRITY_FAILED", "report artifact integrity failed")
        return str(row["media_type"]), content, str(row["sha256"])


def _report_payload(
    title: str,
    template: str,
    workflow: sqlite3.Row,
    findings: list[dict[str, Any]],
    policy_bundle_id: str,
) -> dict[str, Any]:
    return {
        "title": title,
        "template": template,
        "engagement_id": workflow["engagement_id"],
        "policy_bundle_id": policy_bundle_id,
        "testing_period": {
            "started_at": workflow["started_at"],
            "ended_at": workflow["finalized_at"],
        },
        "limitations": ["Draft only; human approval and export-ready status are not implemented."],
        "findings": findings,
    }


def _render(payload: dict[str, Any]) -> dict[str, bytes]:
    markdown = _markdown(payload)
    escaped = html.escape(markdown)
    html_body = (
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>"
        + html.escape(str(payload["title"]))
        + "</title></head><body><pre>"
        + escaped
        + "</pre></body></html>"
    ).encode()
    json_body = canonical_json(payload).encode()
    return {
        "markdown": markdown.encode(),
        "html": html_body,
        "json": json_body,
        "pdf": _pdf(markdown),
    }


def _markdown(payload: dict[str, Any]) -> str:
    lines = [
        f"# {payload['title']}",
        "",
        f"Template: {payload['template']}",
        f"Policy bundle: {payload['policy_bundle_id']}",
        f"Testing period: {payload['testing_period']['started_at'] or 'not recorded'} to "
        f"{payload['testing_period']['ended_at'] or 'not recorded'}",
        "",
        "## Findings",
    ]
    for finding in payload["findings"]:
        lines.extend(
            [
                "",
                f"### {finding['title']}",
                f"Severity: {finding['severity']} (CVSS {finding['cvss']['base_score']})",
                f"CWE: {finding['cwe']}",
                "",
                "#### Reproduction",
                finding["reproduction"],
                "",
                "#### Impact",
                finding["impact"],
                "",
                "#### Remediation",
                finding["remediation"],
            ]
        )
    lines.extend(["", "## Limitations", *[f"- {item}" for item in payload["limitations"]]])
    return "\n".join(lines) + "\n"


def _pdf(text: str) -> bytes:
    safe = text.encode("ascii", errors="replace").decode().replace("\\", "\\\\")
    safe = safe.replace("(", "\\(").replace(")", "\\)")
    lines = safe.splitlines()[:200]
    stream = "BT /F1 9 Tf 40 780 Td 11 TL " + " ".join(
        f"({line[:120]}) Tj T*" for line in lines
    ) + " ET"
    objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        "/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        f"<< /Length {len(stream.encode())} >>\nstream\n{stream}\nendstream",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    body = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(body))
        body.extend(f"{index} 0 obj\n{obj}\nendobj\n".encode())
    xref = len(body)
    body.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        body.extend(f"{offset:010d} 00000 n \n".encode())
    body.extend(
        f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    )
    return bytes(body)


def _identity(value: str, code: str) -> None:
    try:
        UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ReportError(code, "report identity is invalid") from exc


def _timestamp(value: datetime | None) -> str:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise ReportError("REPORT_TIME_INVALID", "report time must be timezone aware")
    return current.astimezone(UTC).isoformat().replace("+00:00", "Z")
