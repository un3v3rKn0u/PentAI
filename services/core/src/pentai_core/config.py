from __future__ import annotations

import os
import re
import sys
from base64 import urlsafe_b64decode
from dataclasses import dataclass
from pathlib import Path

_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DIGEST_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


@dataclass(frozen=True)
class Settings:
    """Local-core configuration with safe loopback defaults."""

    app_name: str = "PentAI Core"
    environment: str = "development"
    host: str = "127.0.0.1"
    port: int = 8741
    database_path: Path = Path("var/pentai.db")
    source_store_path: Path = Path("var/source-blobs")
    source_master_key: bytes | None = None
    policy_signing_key: bytes | None = None
    launch_credential: str | None = None
    test_mode: bool = False
    gateway_runtime_enabled: bool = False
    gateway_runtime: str | None = None
    gateway_runtime_executable: Path | None = None
    gateway_runtime_instance_id: str | None = None
    gateway_network_id: str | None = None
    gateway_probe_image_digest: str | None = None
    gateway_instance_id: str | None = None
    gateway_watchdog_interval_seconds: float = 5

    def validate(self) -> None:
        if self.host not in _LOOPBACK_HOSTS:
            raise ValueError("PentAI Core must bind to a loopback address")
        if not 1 <= self.port <= 65535:
            raise ValueError("PentAI Core port must be from 1 through 65535")
        self._validate_gateway_runtime()
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
        source_master_key = _secret_key("PENTAI_SOURCE_KEY_STDIN", "PENTAI_SOURCE_MASTER_KEY")
        policy_signing_key = _secret_key(
            "PENTAI_POLICY_SIGNING_KEY_STDIN", "PENTAI_POLICY_SIGNING_KEY"
        )
        settings = cls(
            environment=environment,
            host=host,
            port=int(os.getenv("PENTAI_CORE_PORT", "8741")),
            database_path=Path(os.getenv("PENTAI_DATABASE_PATH", "var/pentai.db")),
            source_store_path=Path(os.getenv("PENTAI_SOURCE_STORE_PATH", "var/source-blobs")),
            source_master_key=source_master_key,
            policy_signing_key=policy_signing_key,
            launch_credential=os.getenv("PENTAI_LAUNCH_CREDENTIAL"),
            test_mode=environment == "test" and os.getenv("PENTAI_TEST_MODE") == "1",
            gateway_runtime_enabled=_environment_flag("PENTAI_GATEWAY_RUNTIME_ENABLED"),
            gateway_runtime=os.getenv("PENTAI_GATEWAY_RUNTIME"),
            gateway_runtime_executable=_optional_path("PENTAI_GATEWAY_RUNTIME_EXECUTABLE"),
            gateway_runtime_instance_id=os.getenv("PENTAI_GATEWAY_RUNTIME_INSTANCE_ID"),
            gateway_network_id=os.getenv("PENTAI_GATEWAY_NETWORK_ID"),
            gateway_probe_image_digest=os.getenv("PENTAI_GATEWAY_PROBE_IMAGE_DIGEST"),
            gateway_instance_id=os.getenv("PENTAI_GATEWAY_INSTANCE_ID"),
            gateway_watchdog_interval_seconds=float(
                os.getenv("PENTAI_GATEWAY_WATCHDOG_INTERVAL_SECONDS", "5")
            ),
        )
        settings.validate()
        return settings

    def _validate_gateway_runtime(self) -> None:
        configured = (
            self.gateway_runtime,
            self.gateway_runtime_executable,
            self.gateway_runtime_instance_id,
            self.gateway_network_id,
            self.gateway_probe_image_digest,
            self.gateway_instance_id,
        )
        if not self.gateway_runtime_enabled:
            if any(value is not None for value in configured):
                raise ValueError("Gateway runtime configuration requires explicit enablement")
            return
        if any(value is None for value in configured):
            raise ValueError("Enabled gateway runtime configuration is incomplete")
        executable = self.gateway_runtime_executable
        identities = (
            self.gateway_runtime_instance_id,
            self.gateway_network_id,
            self.gateway_instance_id,
        )
        if (
            self.gateway_runtime not in {"docker", "podman"}
            or executable is None
            or not executable.is_absolute()
            or any(
                not isinstance(value, str) or not _IDENTIFIER_PATTERN.fullmatch(value)
                for value in identities
            )
            or not isinstance(self.gateway_probe_image_digest, str)
            or not _DIGEST_PATTERN.fullmatch(self.gateway_probe_image_digest)
            or not 0.1 <= self.gateway_watchdog_interval_seconds <= 10
        ):
            raise ValueError("Gateway runtime configuration is invalid")


def _secret_key(stdin_flag: str, environment_name: str) -> bytes | None:
    if os.getenv(stdin_flag) == "1":
        encoded = sys.stdin.readline(128).strip()
        if not encoded:
            raise ValueError("A required local secret key is unavailable")
    else:
        encoded = os.getenv(environment_name)
    if encoded is None:
        return None
    try:
        key = urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except ValueError as exc:
        raise ValueError("A required local secret key is invalid") from exc
    if len(key) != 32:
        raise ValueError("A required local secret key is invalid")
    return key


def _environment_flag(name: str) -> bool:
    value = os.getenv(name, "0")
    if value not in {"0", "1"}:
        raise ValueError(f"{name} must be 0 or 1")
    return value == "1"


def _optional_path(name: str) -> Path | None:
    value = os.getenv(name)
    return Path(value) if value is not None else None


def allowed_origins(settings: Settings) -> list[str]:
    origins = ["tauri://localhost", "http://tauri.localhost", "https://tauri.localhost"]
    if settings.environment == "development":
        origins.extend(["http://127.0.0.1:1420", "http://localhost:1420"])
    return origins
