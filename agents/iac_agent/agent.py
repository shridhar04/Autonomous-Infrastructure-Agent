"""
IaC Agent — Infrastructure-as-Code security scanning.
Scans Terraform, Kubernetes YAML, Dockerfiles, Helm, Ansible using Checkov.
"""

import asyncio
import json
from typing import Any, Dict, List

from observability.logging.logger import get_logger
from config.settings import settings

logger = get_logger(__name__)

CHECKOV_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "UNKNOWN": "INFO",
}


class IaCAgent:
    """
    Detects infrastructure misconfigurations in Terraform (HCL),
    Kubernetes YAML, Dockerfiles, Helm charts, Ansible playbooks,
    CloudFormation, and ARM templates using Checkov.
    """

    async def scan(self, context) -> List[Dict[str, Any]]:
        logger.info("IaC scan starting for %s", context.repo_name)
        findings = await self._run_checkov(context)
        logger.info("IaC: %d findings for scan %s", len(findings), context.scan_id)
        return findings

    async def _run_checkov(self, context) -> List[Dict]:
        cmd = [
            "checkov",
            "-d", context.repo_url,
            "--framework", settings.CHECKOV_FRAMEWORK,
            "-o", "json",
            "--compact",
            "--quiet",
        ]

        try:
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(result.communicate(), timeout=300)
            raw = json.loads(stdout.decode())
            return self._normalize_checkov(raw)
        except Exception as exc:
            logger.error("Checkov failed: %s", exc)
            return []

    def _normalize_checkov(self, raw) -> List[Dict]:
        findings = []
        results = raw if isinstance(raw, list) else [raw]

        for scan_result in results:
            for check in scan_result.get("results", {}).get("failed_checks", []):
                findings.append({
                    "scanner": "checkov",
                    "rule_id": f"iac.{check.get('check_id')}",
                    "message": check.get("check_result", {}).get("result", "FAILED"),
                    "severity": CHECKOV_SEVERITY_MAP.get(
                        check.get("severity", "UNKNOWN"), "INFO"
                    ),
                    "language": "terraform",
                    "file_path": check.get("file_path"),
                    "line_number": check.get("file_line_range", [None])[0],
                    "resource": check.get("resource"),
                    "check_name": check.get("check_class"),
                    "guideline": check.get("guideline"),
                    "cve_id": None,
                    "iac_type": self._detect_iac_type(check.get("file_path", "")),
                })
        return findings

    def _detect_iac_type(self, file_path: str) -> str:
        path = file_path.lower()
        if path.endswith(".tf"):
            return "terraform"
        if "dockerfile" in path:
            return "dockerfile"
        if path.endswith((".yaml", ".yml")):
            return "kubernetes" if "helm" not in path else "helm"
        if path.endswith(".json") and "cloudformation" in path:
            return "cloudformation"
        return "unknown"
