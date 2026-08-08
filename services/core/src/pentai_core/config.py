from __future__ import annotations

import os
import re
from base64 import urlsafe_b64decode
from dataclasses import dataclass
from pathlib import Path

_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


@dataclass(frozen=True)
class Settings:
    """Local-core configuration with safe loopback defaults."""

    app_name: str = "PentAI Core"
    environment: str = "development"
    host: str = "127.0.0.1"
    port: int = 8741
    database_path: Path = Path("var/pentai.db")
    launch_credential: str | None = None
    test_mode: bool = False

    def validate(self) -> None:
        if self.host not in _LOOPBACK_HOSTS:
            raise ValueError("PentAI Core must bind to a loopback address")
        if not 1 <= self.port <= 65535:
            raise ValueError("PentAI Core port must be from 1 through 65535")
        if self.test_mode:
            return
        credential = self.launch_credential
        if credential is None or not _TOKEN_PATTERN.fullmatch(credential):
            raise ValueError("A valid per-launch credential is required")
        try:
            decoded = urlsafe_b64decode(credential + "=" * (-len(credential) % 4))
        except ValueError as exc:
            raise ValueError("A valid per-launch credential is required") from exc
        if len(decoded) < 32:
            raise ValueError("A valid per-launch credential is required")

    @classmethod
    def from_environment(cls) -> Settings:
        host = os.getenv("PENTAI_CORE_HOST", "127.0.0.1")
        environment = os.getenv("PENTAI_ENVIRONMENT", "development")
        settings = cls(
            environment=environment,
            host=host,
            port=int(os.getenv("PENTAI_CORE_PORT", "8741")),
            database_path=Path(os.getenv("PENTAI_DATABASE_PATH", "var/pentai.db")),
            launch_credential=os.getenv("PENTAI_LAUNCH_CREDENTIAL"),
            test_mode=environment == "test" and os.getenv("PENTAI_TEST_MODE") == "1",
        )
        settings.validate()
        return settings


def allowed_origins(settings: Settings) -> list[str]:
    origins = ["tauri://localhost", "http://tauri.localhost", "https://tauri.localhost"]
    if settings.environment == "development":
        origins.extend(["http://127.0.0.1:1420", "http://localhost:1420"])
    return origins
