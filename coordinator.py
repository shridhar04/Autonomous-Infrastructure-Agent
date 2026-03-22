"""
Agent Orchestrator — master coordinator for all AI agents.
Receives scan events from Kafka, fans out to specialist agents,
collects findings, and routes to the AI reasoning core.
"""

import asyncio
import logging
from typing import Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum

from agents.sast_agent.agent import SASTAgent
from agents.sca_agent.agent import SCAAgent
from agents.secrets_agent.agent import SecretsAgent
from agents.iac_agent.agent import IaCAgent
from agents.dast_agent.agent import DASTAgent
from agents.remediation_agent.agent import RemediationAgent
from agents.threat_model_agent.agent import ThreatModelAgent
from core.reasoning.engine import ReasoningEngine
from storage.cache.redis_client import RedisClient
from observability.logging.logger import get_logger

logger = get_logger(__name__)


class ScanType(str, Enum):
    FULL = "full"
    SAST_ONLY = "sast"
    SCA_ONLY = "sca"
    SECRETS_ONLY = "secrets"
    IAC_ONLY = "iac"
    CONTAINER = "container"
    PR = "pr"                  # Fast scan for pull requests
    SCHEDULED = "scheduled"    # Nightly deep scan


@dataclass
class ScanContext:
    """Carries all metadata for a single scan job through the pipeline."""
    scan_id: str
    repo_url: str
    repo_name: str
    branch: str
    commit_sha: str
    scan_type: ScanType
    triggered_by: str           # user, webhook, schedule
    pr_number: str | None = None
    changed_files: List[str] = field(default_factory=list)
    languages: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentResult:
    agent_name: str
    findings: List[Dict[str, Any]]
    scan_duration_ms: int
    error: str | None = None


class AgentOrchestrator:
    """
    Orchestrates parallel execution of all security scanning agents.

    Flow:
      1. Receive ScanContext from event bus
      2. Detect languages in the repository
      3. Fan out to relevant agents in parallel
      4. Collect all AgentResults
      5. Send aggregated findings to ReasoningEngine
      6. Trigger notifications and pipeline gates
    """

    def __init__(self):
        self.reasoning_engine = ReasoningEngine()
        self.agents = {
            "sast": SASTAgent(),
            "sca": SCAAgent(),
            "secrets": SecretsAgent(),
            "iac": IaCAgent(),
            "dast": DASTAgent(),
        }
        self.remediation_agent = RemediationAgent()
        self.threat_model_agent = ThreatModelAgent()
        self._running = False

    async def start(self):
        logger.info("Agent Orchestrator starting...")
        await self.reasoning_engine.initialize()
        self._running = True
        logger.info("Agent Orchestrator ready. Agents: %s", list(self.agents.keys()))

    async def stop(self):
        self._running = False
        logger.info("Agent Orchestrator stopped.")

    async def run_scan(self, context: ScanContext) -> Dict[str, Any]:
        """
        Main entry point: orchestrate a full security scan for a repo/commit.
        Returns enriched, deduplicated, scored findings with fix suggestions.
        """
        logger.info(
            "Scan started | id=%s repo=%s branch=%s type=%s",
            context.scan_id, context.repo_name, context.branch, context.scan_type
        )

        # Check cache — skip if same commit was scanned recently
        cache_key = f"scan:{context.repo_name}:{context.commit_sha}"
        cached = await RedisClient.get(cache_key)
        if cached:
            logger.info("Cache hit for scan %s — returning cached results", context.scan_id)
            return cached

        # Detect languages in the repo
        context.languages = await self._detect_languages(context)

        # Select which agents to run based on scan type and detected languages
        agents_to_run = self._select_agents(context)

        # Run all selected agents in parallel
        agent_tasks = [
            self._run_agent_safe(name, agent, context)
            for name, agent in agents_to_run.items()
        ]
        agent_results: List[AgentResult] = await asyncio.gather(*agent_tasks)

        # Aggregate raw findings
        raw_findings = []
        for result in agent_results:
            if result.error:
                logger.warning("Agent %s failed: %s", result.agent_name, result.error)
            else:
                raw_findings.extend(result.findings)

        logger.info(
            "Scan %s: collected %d raw findings from %d agents",
            context.scan_id, len(raw_findings), len(agent_results)
        )

        # Send to AI reasoning core for enrichment, dedup, scoring, fix generation
        processed_result = await self.reasoning_engine.process(
            scan_context=context,
            raw_findings=raw_findings,
        )

        # Cache the result
        await RedisClient.set(
            cache_key,
            processed_result,
            ttl=600  # 10 minutes — same commit unlikely to change
        )

        logger.info(
            "Scan %s complete: %d findings after dedup/enrichment (critical=%d high=%d)",
            context.scan_id,
            processed_result["total_findings"],
            processed_result["severity_counts"].get("CRITICAL", 0),
            processed_result["severity_counts"].get("HIGH", 0),
        )

        return processed_result

    def _select_agents(self, context: ScanContext) -> Dict:
        """Select relevant agents based on scan type and detected languages."""
        if context.scan_type == ScanType.SAST_ONLY:
            return {"sast": self.agents["sast"]}
        if context.scan_type == ScanType.SCA_ONLY:
            return {"sca": self.agents["sca"]}
        if context.scan_type == ScanType.SECRETS_ONLY:
            return {"secrets": self.agents["secrets"]}
        if context.scan_type == ScanType.IAC_ONLY:
            return {"iac": self.agents["iac"]}
        if context.scan_type == ScanType.PR:
            # Fast PR scan: SAST + secrets only
            return {k: v for k, v in self.agents.items() if k in ("sast", "secrets")}

        # Full or scheduled scan — run everything
        selected = dict(self.agents)

        # Skip DAST if no web frameworks detected
        if not self._has_web_framework(context.languages):
            selected.pop("dast", None)

        return selected

    async def _run_agent_safe(
        self, name: str, agent, context: ScanContext
    ) -> AgentResult:
        """Run a single agent with error isolation — one agent failing doesn't block others."""
        import time
        start = time.monotonic()
        try:
            findings = await agent.scan(context)
            duration_ms = int((time.monotonic() - start) * 1000)
            return AgentResult(
                agent_name=name,
                findings=findings,
                scan_duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            logger.error("Agent %s raised exception: %s", name, exc, exc_info=True)
            return AgentResult(
                agent_name=name,
                findings=[],
                scan_duration_ms=duration_ms,
                error=str(exc),
            )

    async def _detect_languages(self, context: ScanContext) -> List[str]:
        """Detect programming languages present in the repository."""
        # In production: clone repo, run linguist or similar
        # Here we return a sensible default for demonstration
        return ["python", "javascript", "dockerfile", "terraform"]

    def _has_web_framework(self, languages: List[str]) -> bool:
        web_langs = {"javascript", "typescript", "python", "ruby", "php", "java", "go"}
        return bool(set(languages) & web_langs)
