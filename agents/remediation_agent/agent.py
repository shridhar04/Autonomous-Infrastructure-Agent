"""
Remediation Agent — Generates actionable fix suggestions and
optionally opens PRs with automated patches.
"""

import logging
from typing import Any, Dict, List

from anthropic import AsyncAnthropic
from config.settings import settings
from observability.logging.logger import get_logger

logger = get_logger(__name__)


class RemediationAgent:
    """
    Takes processed findings and generates:
    - Natural language explanations
    - Code patches for automated PR comments
    - Ticket descriptions for Jira/GitHub Issues
    - Developer-friendly learning resources
    """

    def __init__(self):
        self.llm = AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)

    async def generate_pr_comment(
        self, findings: List[Dict[str, Any]], scan_context
    ) -> str:
        """Generate a structured PR review comment with all findings."""
        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        high = [f for f in findings if f.get("severity") == "HIGH"]
        medium = [f for f in findings if f.get("severity") == "MEDIUM"]
        low = [f for f in findings if f.get("severity") in ("LOW", "INFO")]

        lines = [
            "## SecureOps AI Security Review",
            "",
            f"Scanned commit `{scan_context.commit_sha[:8]}` on branch `{scan_context.branch}`",
            "",
            "### Summary",
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| Critical | {len(critical)} |",
            f"| High     | {len(high)} |",
            f"| Medium   | {len(medium)} |",
            f"| Low      | {len(low)} |",
            "",
        ]

        if critical:
            lines += ["### Critical Findings (Build Blocked)", ""]
            for f in critical:
                lines += self._format_finding(f)

        if high:
            lines += ["### High Severity Findings", ""]
            for f in high:
                lines += self._format_finding(f)

        if medium:
            lines += ["### Medium Severity Findings", ""]
            for f in medium:
                lines += self._format_finding(f)

        if not findings:
            lines.append("No security violations detected. Build approved.")

        return "\n".join(lines)

    def _format_finding(self, finding: Dict) -> List[str]:
        lines = [
            f"#### `{finding.get('rule_id')}` — {finding.get('file_path')}:{finding.get('line_number')}",
            f"**Scanner:** {finding.get('scanner')} | "
            f"**Severity:** {finding.get('severity')} | "
            f"**CVE:** {finding.get('cve_id', 'N/A')}",
            "",
            f"{finding.get('message', '')}",
            "",
        ]

        if finding.get("fix_suggestion"):
            lines += [
                "<details><summary>AI Fix Suggestion</summary>",
                "",
                finding["fix_suggestion"],
                "",
                "</details>",
                "",
            ]

        return lines

    async def generate_ticket(self, finding: Dict, scan_context) -> Dict:
        """Generate a Jira/GitHub Issue ticket body for a finding."""
        return {
            "title": f"[SecureOps] {finding.get('severity')} - {finding.get('rule_id')} in {finding.get('file_path')}",
            "body": finding.get("fix_suggestion", finding.get("message", "")),
            "labels": ["security", finding.get("severity", "").lower()],
            "priority": "high" if finding.get("severity") in ("CRITICAL", "HIGH") else "medium",
        }
