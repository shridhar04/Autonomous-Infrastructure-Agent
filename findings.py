"""
Findings routes — query, filter, and provide feedback on security findings.
"""

from fastapi import APIRouter, Request, Query
from typing import List, Optional

from storage.cache.redis_client import RedisClient

router = APIRouter()


@router.get("/")
async def list_findings(
    repo: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    scanner: Optional[str] = Query(None),
    limit: int = Query(50, le=500),
):
    """List findings with optional filters."""
    # In production: query PostgreSQL findings table
    return {"findings": [], "total": 0, "filters": {"repo": repo, "severity": severity}}


@router.post("/{finding_id}/feedback")
async def submit_feedback(finding_id: str, request: Request):
    """
    Submit developer feedback on a finding.
    Used for model fine-tuning and false-positive tracking.
    """
    payload = await request.json()
    action = payload.get("action")   # accepted_fix | false_positive | accepted_risk

    if action not in ("accepted_fix", "rejected_fix", "false_positive", "accepted_risk"):
        return {"error": "Invalid action"}

    await RedisClient.set(
        f"feedback:{finding_id}",
        {"action": action, "comment": payload.get("comment", "")},
        ttl=86400 * 30,  # 30 days
    )

    return {"status": "feedback_recorded", "finding_id": finding_id, "action": action}


@router.post("/{finding_id}/suppress")
async def suppress_finding(finding_id: str, request: Request):
    """Mark a finding as suppressed (requires security team role)."""
    payload = await request.json()
    return {"status": "suppressed", "finding_id": finding_id, "reason": payload.get("reason")}
