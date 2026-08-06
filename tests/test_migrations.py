from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from pentai_core.migrate import migrate


class MigrationTests(unittest.TestCase):
    def test_initial_migration_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "pentai.db"
            self.assertEqual(migrate(database), ["0001"])
            self.assertEqual(migrate(database), [])
            with sqlite3.connect(database) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
            self.assertTrue(
                {"programs", "engagements", "policy_bundles", "audit_events", "outbox"}
                <= tables
            )


if __name__ == "__main__":
    unittest.main()
