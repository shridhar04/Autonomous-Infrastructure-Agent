"""
Secrets Agent — Detects leaked credentials, API keys, and tokens.
Wraps Gitleaks and TruffleHog for comprehensive secrets detection.
"""

import asyncio
import json
from typing import Any, Dict, List

from observability.logging.logger import get_logger
from config.settings import settings

logger = get_logger(__name__)


class SecretsAgent:
    """
    Scans repositories and git history for secrets, API keys,
    private keys, tokens, and credentials using Gitleaks + TruffleHog.
    All secrets findings are treated as HIGH or CRITICAL severity.
    """

    async def scan(self, context) -> List[Dict[str, Any]]:
        logger.info("Secrets scan starting for %s", context.repo_name)

        findings = []

        gitleaks_findings = await self._run_gitleaks(context)
        findings.extend(gitleaks_findings)

        trufflehog_findings = await self._run_trufflehog(context)
        findings.extend(trufflehog_findings)

        # Deduplicate within secrets findings
        seen = set()
        unique = []
        for f in findings:
            key = (f.get("file_path"), f.get("line_number"), f.get("secret_type"))
            if key not in seen:
                seen.add(key)
                unique.append(f)

        logger.info("Secrets: %d unique findings for scan %s", len(unique), context.scan_id)
        return unique

    async def _run_gitleaks(self, context) -> List[Dict]:
        cmd = [
            "gitleaks",
            "detect",
            "--source", context.repo_url,
            "--config", settings.GITLEAKS_CONFIG_PATH,
            "--report-format", "json",
            "--no-banner",
            "--exit-code", "0",      # Don't fail — we handle the output
        ]

        try:
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(result.communicate(), timeout=120)
            raw = json.loads(stdout.decode() or "[]")
            return self._normalize_gitleaks(raw)
        except Exception as exc:
            logger.error("Gitleaks failed: %s", exc)
            return []

    def _normalize_gitleaks(self, raw: List[Dict]) -> List[Dict]:
        findings = []
        for leak in raw:
            secret_value = leak.get("Secret", "")
            findings.append({
                "scanner": "gitleaks",
                "rule_id": f"secrets.{leak.get('RuleID', 'unknown')}",
                "message": f"Leaked secret detected: {leak.get('Description', '')}",
                "severity": "CRITICAL",   # All secrets are critical
                "secret_type": leak.get("RuleID"),
                "file_path": leak.get("File"),
                "line_number": leak.get("StartLine"),
                "language": None,
                "commit_sha": leak.get("Commit"),
                "author": leak.get("Author"),
                "secret_masked": self._mask_secret(secret_value),
                "entropy": leak.get("Entropy"),
                "tags": leak.get("Tags", []),
                "cve_id": None,
            })
        return findings

    async def _run_trufflehog(self, context) -> List[Dict]:
        cmd = [
            "trufflehog",
            "filesystem",
            "--json",
            "--no-update",
            context.repo_url,
        ]

        try:
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(result.communicate(), timeout=120)
            lines = [l for l in stdout.decode().strip().split("\n") if l]
            raw = [json.loads(l) for l in lines if l.startswith("{")]
            return self._normalize_trufflehog(raw)
        except Exception as exc:
            logger.error("TruffleHog failed: %s", exc)
            return []

    def _normalize_trufflehog(self, raw: List[Dict]) -> List[Dict]:
        findings = []
        for finding in raw:
            findings.append({
                "scanner": "trufflehog",
                "rule_id": f"secrets.{finding.get('DetectorName', 'unknown').lower()}",
                "message": f"Verified secret: {finding.get('DetectorName', '')}",
                "severity": "CRITICAL" if finding.get("Verified") else "HIGH",
                "secret_type": finding.get("DetectorName"),
                "file_path": finding.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file"),
                "line_number": finding.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line"),
                "language": None,
                "verified": finding.get("Verified", False),
                "secret_masked": "***REDACTED***",
                "cve_id": None,
            })
        return findings

    def _mask_secret(self, secret: str) -> str:
        """Show only first 4 chars + mask the rest."""
        if not secret or len(secret) < 6:
            return "***"
        return secret[:4] + "*" * (len(secret) - 4)
