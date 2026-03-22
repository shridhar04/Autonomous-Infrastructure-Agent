"""
DAST Agent — Dynamic Application Security Testing.
Runs OWASP ZAP against live staging endpoints to find runtime vulnerabilities.
"""

import asyncio
import json
import time
from typing import Any, Dict, List

from observability.logging.logger import get_logger
from config.settings import settings

logger = get_logger(__name__)

ZAP_RISK_MAP = {
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
    "Informational": "INFO",
}


class DASTAgent:
    """
    Performs dynamic scanning using OWASP ZAP in headless daemon mode.
    Targets staging/preview environments only — never production.

    Scans for:
    - SQL injection (active scan)
    - XSS (reflected, stored, DOM)
    - SSRF
    - Broken authentication
    - Security misconfigurations
    - Sensitive data exposure
    - CSRF
    """

    async def scan(self, context) -> List[Dict[str, Any]]:
        target_url = context.metadata.get("staging_url")
        if not target_url:
            logger.info("No staging_url in context — skipping DAST for scan %s", context.scan_id)
            return []

        logger.info("DAST scan starting against %s", target_url)

        findings = []

        # Step 1: Spider the target
        await self._spider(target_url)

        # Step 2: Active scan
        await self._active_scan(target_url)

        # Step 3: Collect and normalize alerts
        findings = await self._collect_alerts(target_url)

        logger.info("DAST: %d findings for scan %s", len(findings), context.scan_id)
        return findings

    async def _spider(self, target_url: str):
        """Run ZAP spider to discover all endpoints."""
        cmd = [
            "zap-cli", "--port", "8090",
            "spider", target_url
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)
        except Exception as exc:
            logger.warning("ZAP spider failed: %s", exc)

    async def _active_scan(self, target_url: str):
        """Run ZAP active scan for vulnerability detection."""
        cmd = [
            "zap-cli", "--port", "8090",
            "active-scan", "--scanners", "all",
            target_url
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=600)
        except Exception as exc:
            logger.warning("ZAP active scan failed: %s", exc)

    async def _collect_alerts(self, target_url: str) -> List[Dict]:
        """Retrieve and normalize ZAP alerts."""
        cmd = [
            "zap-cli", "--port", "8090",
            "report", "--output-format", "json",
            "--output", "/tmp/zap_report.json"
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=60)

            with open("/tmp/zap_report.json") as f:
                raw = json.load(f)

            return self._normalize_zap(raw)
        except Exception as exc:
            logger.error("ZAP report collection failed: %s", exc)
            return []

    def _normalize_zap(self, raw: Dict) -> List[Dict]:
        findings = []
        for site in raw.get("site", []):
            for alert in site.get("alerts", []):
                for instance in alert.get("instances", [{}]):
                    findings.append({
                        "scanner": "zap",
                        "rule_id": f"dast.{alert.get('pluginid', 'unknown')}",
                        "message": alert.get("desc", ""),
                        "severity": ZAP_RISK_MAP.get(alert.get("riskdesc", "Low").split()[0], "LOW"),
                        "language": None,
                        "file_path": instance.get("uri", ""),
                        "line_number": None,
                        "evidence": instance.get("evidence", ""),
                        "solution": alert.get("solution", ""),
                        "cwe_id": f"CWE-{alert.get('cweid')}" if alert.get("cweid") else None,
                        "wasc_id": alert.get("wascid"),
                        "references": alert.get("reference", "").split("\n"),
                        "cve_id": None,
                    })
        return findings
