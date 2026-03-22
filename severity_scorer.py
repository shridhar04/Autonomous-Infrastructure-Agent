"""
Severity Scorer — Computes a final normalized severity score using
CVSS base score, EPSS exploitation probability, and business context rules.
"""

from typing import Dict, Any
from config.settings import settings


class SeverityScorer:
    """
    Combines CVSS + EPSS + business context to produce a final severity label.

    Logic:
    - CVSS >= 9.0 AND EPSS >= 0.5  → CRITICAL
    - CVSS >= 7.0                   → HIGH
    - CVSS >= 4.0                   → MEDIUM
    - CVSS < 4.0                    → LOW
    - No CVSS available             → Keep scanner's severity
    - Verified secrets              → Always CRITICAL
    """

    def score(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        # Secrets are always critical
        if finding.get("scanner") in ("gitleaks", "trufflehog"):
            if finding.get("verified"):
                finding["severity"] = "CRITICAL"
                finding["severity_rationale"] = "Verified secret detected"
            else:
                finding["severity"] = "HIGH"
                finding["severity_rationale"] = "Unverified secret detected"
            return finding

        cvss = finding.get("cvss_score")
        epss = finding.get("epss_score", 0.0)

        if cvss is None:
            # No CVSS available — keep scanner's original severity
            finding["severity_rationale"] = "No CVSS score — using scanner severity"
            return finding

        # Severity upgrade: if actively exploited (high EPSS), bump up
        if cvss >= settings.GATE_CVSS_BLOCK_THRESHOLD or (cvss >= 7.0 and epss >= settings.GATE_EPSS_BLOCK_THRESHOLD):
            severity = "CRITICAL"
        elif cvss >= 7.0:
            severity = "HIGH"
        elif cvss >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        finding["severity"] = severity
        finding["severity_rationale"] = (
            f"CVSS={cvss}, EPSS={epss:.3f} (exploitation probability)"
        )
        return finding
