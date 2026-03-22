"""Alerts API routes."""
from fastapi import APIRouter
router = APIRouter()

@router.get("/")
async def list_alerts(limit: int = 50):
    return {"alerts": [], "total": 0}
