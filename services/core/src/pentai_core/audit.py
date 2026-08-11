from __future__ import annotations

import sqlite3
from typing import Any
from uuid import uuid4

from pentai_policy import canonical_json, content_hash


def append_audit_event(
    connection: sqlite3.Connection,
    *,
    action: str,
    subject_type: str,
    subject_id: str,
    actor_type: str,
    actor_id: str,
    data: dict[str, Any],
    occurred_at: str,
) -> dict[str, Any]:
    previous = connection.execute(
        "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    previous_hash = previous["event_hash"] if previous else None
    event = {
        "event_id": str(uuid4()),
        "occurred_at": occurred_at,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "action": action,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "data": data,
        "previous_hash": previous_hash,
    }
    event_hash = content_hash(event)
    connection.execute(
        """
        INSERT INTO audit_events(
            event_id, occurred_at, actor_type, actor_id, action, subject_type,
            subject_id, data_json, previous_hash, event_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event["event_id"],
            occurred_at,
            actor_type,
            actor_id,
            action,
            subject_type,
            subject_id,
            canonical_json(data),
            previous_hash,
            event_hash,
        ),
    )
    return {**event, "event_hash": event_hash}
