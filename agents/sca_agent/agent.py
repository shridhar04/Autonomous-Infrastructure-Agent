"""
SCA Agent — Software Composition Analysis.
Scans dependency manifests for known CVEs using Grype.
"""

import asyncio
import json
import logging
from typing import Any, Dict, List

from observability.logging.logger import get_logger
from config.settings import settings

logger = get_logger(__name__)

GRYPE_SEVERITY_MAP = {
    "Critical": "CRITICAL",
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
    "Negligible": "INFO",
}


class SCAAgent:
    """
    Dependency vulnerability scanning using Grype.
    Detects CVEs in npm, pip, Maven, Cargo, Go modules, RubyGems, Composer, NuGet, etc.
    """

    async def scan(self, context) -> List[Dict[str, Any]]:
        logger.info("SCA scan starting for %s", context.repo_name)
        findings = await self._run_grype(context)
        logger.info("SCA: %d findings for scan %s", len(findings), context.scan_id)
        return findings

    async def _run_grype(self, context) -> List[Dict]:
        cmd = [
            "grype",
            f"dir:{context.repo_url}",
            "-o", "json",
            "--only-fixed",         # Focus on vulnerabilities with available fixes
            f"--fail-on={settings.TRIVY_SEVERITY.split(',')[0].lower()}",
        ]

        try:
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=300)
            return self._normalize_grype(json.loads(stdout.decode()))
        except Exception as exc:
            logger.error("Grype failed: %s", exc)
            return []

    def _normalize_grype(self, raw: Dict) -> List[Dict]:
        findings = []
        for match in raw.get("matches", []):
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            findings.append({
                "scanner": "grype",
                "rule_id": f"sca.{vuln.get('id', 'UNKNOWN')}",
                "message": vuln.get("description", ""),
                "severity": GRYPE_SEVERITY_MAP.get(vuln.get("severity", "Low"), "LOW"),
                "language": artifact.get("language", "unknown"),
                "file_path": artifact.get("locations", [{}])[0].get("path"),
                "line_number": None,
                "cve_id": vuln.get("id"),
                "cvss_score": self._extract_cvss(vuln),
                "fix_version": vuln.get("fix", {}).get("versions", [None])[0],
                "package_name": artifact.get("name"),
                "package_version": artifact.get("version"),
                "package_type": artifact.get("type"),
                "references": vuln.get("urls", []),
            })
        return findings

    def _extract_cvss(self, vuln: Dict) -> float | None:
        for cvss in vuln.get("cvss", []):
            if cvss.get("version", "").startswith("3"):
                return cvss.get("metrics", {}).get("baseScore")
        return None
