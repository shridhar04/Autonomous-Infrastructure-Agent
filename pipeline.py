"""Pipeline gate API routes."""
from fastapi import APIRouter, Request
router = APIRouter()

@router.get("/{scan_id}/gate")
async def get_gate_decision(scan_id: str):
    from storage.cache.redis_client import RedisClient
    result = await RedisClient.get(f"gate:{scan_id}")
    if not result:
        return {"status": "pending", "scan_id": scan_id}
    return result

@router.post("/exception")
async def create_exception(request: Request):
    """Create a CISO-approved policy exception for a finding fingerprint."""
    payload = await request.json()
    from storage.cache.redis_client import RedisClient
    fp = payload.get("fingerprint")
    ttl = payload.get("duration_days", 30) * 86400
    await RedisClient.set(
        f"exception:{fp}",
        {"fingerprint": fp, "reason": payload.get("reason"), "approved_by": payload.get("approved_by")},
        ttl=ttl,
    )
    return {"status": "exception_created", "fingerprint": fp}
