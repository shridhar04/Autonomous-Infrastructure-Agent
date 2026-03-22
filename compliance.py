"""Compliance and SBOM API routes."""
from fastapi import APIRouter, Request
router = APIRouter()

@router.get("/report/{scan_id}")
async def compliance_report(scan_id: str):
    from storage.cache.redis_client import RedisClient
    report = await RedisClient.get(f"compliance:{scan_id}")
    if not report:
        return {"status": "not_found", "scan_id": scan_id}
    return report

@router.get("/sbom/{scan_id}")
async def get_sbom(scan_id: str):
    from storage.cache.redis_client import RedisClient
    sbom = await RedisClient.get(f"sbom:{scan_id}")
    if not sbom:
        return {"status": "not_found", "scan_id": scan_id}
    return sbom
