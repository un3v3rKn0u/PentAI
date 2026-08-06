from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from pentai_core import __version__
from pentai_core.config import settings


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    execution_enabled: bool


app = FastAPI(
    title="PentAI Local Core",
    version=__version__,
    docs_url=None,
    redoc_url=None,
)


@app.get("/api/v1/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        version=__version__,
        environment=settings.environment,
        execution_enabled=False,
    )


@app.get("/api/v1/safety-state")
def safety_state() -> dict[str, object]:
    return {
        "active_policy": None,
        "network_attested": False,
        "execution_enabled": False,
        "reason": "Phase 0 scaffold: target execution is not implemented",
    }
