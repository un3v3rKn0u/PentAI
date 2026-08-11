from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from pentai_core.migrate import migrate
from pentai_policy.document import contract_issues

from scripts.owned_fixture_authority import (
    OwnedFixtureDnsBackend,
    prepare_owned_fixture_session,
)


def test_owned_fixture_builds_complete_committed_authority(tmp_path: Path) -> None:
    database = tmp_path / "authority.db"
    migrate(database)

    authority, session = prepare_owned_fixture_session(
        database_path=database,
        source_store_path=tmp_path / "sources",
        maximum_response_bytes=32,
    )
    start = authority.commit_gateway_request_start(str(session["session_id"]))

    assert contract_issues(session, "gateway-session-v1.schema.json") == ()
    assert contract_issues(start, "gateway-request-start-v1.schema.json") == ()
    assert start["status"] == "committed"
    assert start["execution_enabled"] is False
    assert authority.verify_audit_chain()["valid"] is True
    with closing(sqlite3.connect(database)) as connection:
        stored = connection.execute(
            """
            SELECT br.status, grr.status, ag.used_at, da.decision_json
            FROM gateway_request_starts grs
            JOIN budget_reservations br USING (reservation_id)
            JOIN gateway_rate_reservations grr USING (reservation_id)
            JOIN action_grants ag ON ag.grant_id = grs.grant_id
            JOIN gateway_sessions gs USING (session_id)
            JOIN destination_authorizations da
              ON da.authorization_id = gs.destination_authorization_id
            WHERE grs.start_id = ?
            """,
            (start["start_id"],),
        ).fetchone()
    assert stored[0:2] == ("committed", "committed")
    assert stored[2] is not None
    assert '"pinned_addresses":["192.0.2.20"]' in stored[3]


@pytest.mark.parametrize("maximum_response_bytes", [0, 1_048_577])
def test_owned_fixture_denies_invalid_response_bounds(
    tmp_path: Path, maximum_response_bytes: int
) -> None:
    database = tmp_path / "authority.db"
    migrate(database)
    with pytest.raises(ValueError, match="response bound"):
        prepare_owned_fixture_session(
            database_path=database,
            source_store_path=tmp_path / "sources",
            maximum_response_bytes=maximum_response_bytes,
        )
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT COUNT(*) FROM programs").fetchone()[0] == 0


def test_owned_fixture_dns_backend_denies_every_other_tuple() -> None:
    backend = OwnedFixtureDnsBackend()

    assert backend.resolve("example.test", 8080).addresses == ("192.0.2.20",)
    assert backend.resolve("example.test", 80).addresses == ()
    assert backend.resolve("other.test", 8080).addresses == ()
