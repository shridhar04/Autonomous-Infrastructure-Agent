"""
Health check endpoints for Kubernetes liveness and readiness probes.
"""

from fastapi import APIRouter, Request
from storage.cache.redis_client import RedisClient

router = APIRouter()


@router.get("/")
async def health():
    return {"status": "ok", "service": "secureops-ai"}


@router.get("/ready")
async def readiness(request: Request):
    """Readiness probe — checks all downstream dependencies."""
    checks = {}

    # Redis
    try:
        await RedisClient.get("health:ping")
        checks["redis"] = "ok"
    except Exception:
        checks["redis"] = "unreachable"

    # Orchestrator
    try:
        orchestrator = request.app.state.orchestrator
        checks["orchestrator"] = "ok" if orchestrator._running else "stopped"
    except Exception:
        checks["orchestrator"] = "error"

    all_ok = all(v == "ok" for v in checks.values())
    return {"status": "ready" if all_ok else "degraded", "checks": checks}
