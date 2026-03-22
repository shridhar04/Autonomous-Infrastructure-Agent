"""
Scan routes — REST API endpoints for triggering and querying security scans.
"""

import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel, HttpUrl

from agents.orchestrator.coordinator import AgentOrchestrator, ScanContext, ScanType
from observability.logging.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()


class ScanRequest(BaseModel):
    repo_url: str
    repo_name: str
    branch: str = "main"
    commit_sha: str
    scan_type: ScanType = ScanType.FULL
    pr_number: Optional[str] = None
    changed_files: List[str] = []
    triggered_by: str = "api"


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def trigger_scan(
    request: Request,
    payload: ScanRequest,
    background_tasks: BackgroundTasks,
):
    """
    Trigger a security scan for a repository commit.
    Returns immediately with scan_id; runs asynchronously.
    """
    scan_id = str(uuid.uuid4())
    orchestrator: AgentOrchestrator = request.app.state.orchestrator

    context = ScanContext(
        scan_id=scan_id,
        repo_url=payload.repo_url,
        repo_name=payload.repo_name,
        branch=payload.branch,
        commit_sha=payload.commit_sha,
        scan_type=payload.scan_type,
        triggered_by=payload.triggered_by,
        pr_number=payload.pr_number,
        changed_files=payload.changed_files,
    )

    background_tasks.add_task(orchestrator.run_scan, context)

    logger.info("Scan %s queued for %s @ %s", scan_id, payload.repo_name, payload.commit_sha)

    return ScanResponse(
        scan_id=scan_id,
        status="queued",
        message=f"Scan {scan_id} queued. Poll /api/v1/scans/{scan_id} for results.",
    )


@router.get("/{scan_id}")
async def get_scan_result(scan_id: str, request: Request):
    """Retrieve results for a completed scan."""
    from storage.cache.redis_client import RedisClient
    result = await RedisClient.get(f"scan_result:{scan_id}")
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found or still running")
    return result


@router.post("/webhook/github")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    """
    GitHub webhook endpoint — auto-triggered on push and pull_request events.
    Validates HMAC signature before processing.
    """
    import hmac, hashlib
    from config.settings import settings

    payload = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")
    expected = "sha256=" + hmac.new(
        settings.SECRET_KEY.encode(), payload, hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    event_type = request.headers.get("X-GitHub-Event")
    data = await request.json()
    orchestrator: AgentOrchestrator = request.app.state.orchestrator

    if event_type == "push":
        context = ScanContext(
            scan_id=str(uuid.uuid4()),
            repo_url=data["repository"]["clone_url"],
            repo_name=data["repository"]["full_name"],
            branch=data["ref"].replace("refs/heads/", ""),
            commit_sha=data["head_commit"]["id"],
            scan_type=ScanType.FULL,
            triggered_by="github-webhook",
            changed_files=[f for c in data.get("commits", []) for f in c.get("modified", []) + c.get("added", [])],
        )
        background_tasks.add_task(orchestrator.run_scan, context)

    elif event_type == "pull_request" and data.get("action") in ("opened", "synchronize"):
        context = ScanContext(
            scan_id=str(uuid.uuid4()),
            repo_url=data["repository"]["clone_url"],
            repo_name=data["repository"]["full_name"],
            branch=data["pull_request"]["head"]["ref"],
            commit_sha=data["pull_request"]["head"]["sha"],
            scan_type=ScanType.PR,
            triggered_by="github-webhook",
            pr_number=str(data["pull_request"]["number"]),
        )
        background_tasks.add_task(orchestrator.run_scan, context)

    return {"status": "accepted"}
