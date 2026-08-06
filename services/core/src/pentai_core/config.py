from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    """Local-core configuration with safe loopback defaults."""

    app_name: str = "PentAI Core"
    environment: str = "development"
    host: str = "127.0.0.1"
    port: int = 8741
    database_path: Path = Path("var/pentai.db")

    @classmethod
    def from_environment(cls) -> Settings:
        host = os.getenv("PENTAI_CORE_HOST", "127.0.0.1")
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("PentAI Core must bind to a loopback address")
        return cls(
            environment=os.getenv("PENTAI_ENVIRONMENT", "development"),
            host=host,
            port=int(os.getenv("PENTAI_CORE_PORT", "8741")),
            database_path=Path(os.getenv("PENTAI_DATABASE_PATH", "var/pentai.db")),
        )


settings = Settings.from_environment()
