from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import Lock

_HANDLERS: dict[Path, Callable[[], None]] = {}
_HANDLERS_LOCK = Lock()


def register_storage_failure_handler(path: Path, handler: Callable[[], None]) -> None:
    with _HANDLERS_LOCK:
        _HANDLERS[path.resolve()] = handler


def _storage_failure(path: Path, error: sqlite3.Error) -> None:
    code = getattr(error, "sqlite_errorcode", None)
    primary_code = code & 0xFF if isinstance(code, int) else None
    storage_codes = {
        sqlite3.SQLITE_CANTOPEN,
        sqlite3.SQLITE_CORRUPT,
        sqlite3.SQLITE_FULL,
        sqlite3.SQLITE_IOERR,
        sqlite3.SQLITE_NOTADB,
        sqlite3.SQLITE_READONLY,
    }
    message = str(error).lower()
    if primary_code not in storage_codes and not any(
        marker in message
        for marker in ("disk is full", "disk i/o error", "malformed", "readonly database")
    ):
        return
    with _HANDLERS_LOCK:
        handler = _HANDLERS.get(path.resolve())
    if handler is not None:
        handler()


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = FULL")
    return connection


@contextmanager
def transaction(path: Path) -> Iterator[sqlite3.Connection]:
    connection: sqlite3.Connection | None = None
    try:
        connection = connect(path)
        with connection:
            yield connection
    except sqlite3.Error as exc:
        _storage_failure(path, exc)
        raise
    finally:
        if connection is not None:
            connection.close()
