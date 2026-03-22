"""
AI Reasoning Engine — the intelligence core of SecureOps AI.

Responsibilities:
  1. Deduplicate findings from multiple scanners
  2. Enrich each finding with CVE/NVD/EPSS data
  3. Score severity using CVSS + EPSS + business context
  4. Generate natural-language fix suggestions via LLM
  5. Map violations to compliance frameworks
  6. Store feedback signals for continuous improvement
"""

import hashlib
import json
import logging
from typing import Any, Dict, List

from anthropic import AsyncAnthropic

from core.enrichment.cve_enricher import CVEEnricher
from core.scoring.severity_scorer import SeverityScorer
from core.feedback.feedback_store import FeedbackStore
from storage.cache.redis_client import RedisClient
from storage.vector.weaviate_client import WeaviateClient
from config.settings import settings
from observability.logging.logger import get_logger

logger = get_logger(__name__)

SYSTEM_PROMPT = """You are SecureOps AI, an expert security engineer specializing in
application security, DevSecOps, and vulnerability remediation. You analyze security
findings from static analysis, dependency scans, and secrets detection tools.

For each finding you must:
1. Explain the vulnerability clearly in plain language
2. Describe the precise risk and potential attack scenario
3. Provide a concrete, language-appropriate code fix
4. Suggest preventive measures to avoid recurrence
5. Reference relevant OWASP / CWE / CVE identifiers

Always be precise, actionable, and developer-friendly. Tailor fixes to the exact
language, framework, and context provided."""


class ReasoningEngine:
    """
    Central AI reasoning layer that transforms raw scanner findings
    into enriched, actionable security intelligence.
    """

    def __init__(self):
        self.llm = AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
        self.cve_enricher = CVEEnricher()
        self.severity_scorer = SeverityScorer()
        self.feedback_store = FeedbackStore()
        self.vector_client = WeaviateClient()

    async def initialize(self):
        await self.cve_enricher.initialize()
        logger.info("ReasoningEngine initialized.")

    async def process(
        self,
        scan_context,
        raw_findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Full reasoning pipeline: dedup → enrich → score → fix → compliance map.
        Returns a structured result ready for pipeline gate evaluation and alerts.
        """

        # Step 1: Deduplicate across scanners
        deduplicated = self._deduplicate(raw_findings)
        logger.info("Dedup: %d → %d findings", len(raw_findings), len(deduplicated))

        # Step 2: Enrich with CVE / EPSS data
        enriched = await self._enrich_batch(deduplicated)

        # Step 3: Score severity
        scored = [self.severity_scorer.score(f) for f in enriched]

        # Step 4: Generate fix suggestions for non-info findings
        scored_with_fixes = await self._generate_fixes_batch(scored, scan_context)

        # Step 5: Map to compliance frameworks
        final = [self._map_compliance(f) for f in scored_with_fixes]

        # Step 6: Store in vector DB for similarity search
        await self._index_findings(final, scan_context.scan_id)

        # Build summary
        severity_counts = self._count_severities(final)
        gate_decision = self._evaluate_gate(severity_counts)

        return {
            "scan_id": scan_context.scan_id,
            "repo": scan_context.repo_name,
            "commit_sha": scan_context.commit_sha,
            "total_findings": len(final),
            "severity_counts": severity_counts,
            "gate_decision": gate_decision,   # BLOCK | WARN | PASS
            "findings": final,
        }

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def _deduplicate(self, findings: List[Dict]) -> List[Dict]:
        """
        Deduplicate findings using a fingerprint of (rule_id, file, line, language).
        Merges duplicate findings and notes which scanners reported them.
        """
        seen: Dict[str, Dict] = {}
        for f in findings:
            fp = self._fingerprint(f)
            if fp in seen:
                seen[fp].setdefault("reported_by", []).append(f.get("scanner"))
            else:
                f["reported_by"] = [f.get("scanner")]
                seen[fp] = f
        return list(seen.values())

    def _fingerprint(self, finding: Dict) -> str:
        key = f"{finding.get('rule_id')}:{finding.get('file_path')}:{finding.get('line_number')}:{finding.get('language')}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    # ------------------------------------------------------------------
    # CVE Enrichment
    # ------------------------------------------------------------------

    async def _enrich_batch(self, findings: List[Dict]) -> List[Dict]:
        """Enrich all findings with CVE/NVD/EPSS data (parallel, cached)."""
        tasks = [self._enrich_one(f) for f in findings]
        import asyncio
        return await asyncio.gather(*tasks)

    async def _enrich_one(self, finding: Dict) -> Dict:
        cve_id = finding.get("cve_id")
        if not cve_id:
            return finding

        cache_key = f"cve:{cve_id}"
        cached = await RedisClient.get(cache_key)
        if cached:
            finding.update(cached)
            return finding

        enriched_data = await self.cve_enricher.fetch(cve_id)
        if enriched_data:
            finding.update(enriched_data)
            await RedisClient.set(cache_key, enriched_data, ttl=settings.CACHE_CVE_TTL)

        return finding

    # ------------------------------------------------------------------
    # Fix generation via LLM
    # ------------------------------------------------------------------

    async def _generate_fixes_batch(
        self, findings: List[Dict], scan_context
    ) -> List[Dict]:
        """Generate fix suggestions for HIGH/CRITICAL findings in parallel."""
        import asyncio
        tasks = []
        for f in findings:
            if f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM"):
                tasks.append(self._generate_fix(f, scan_context))
            else:
                tasks.append(asyncio.coroutine(lambda x: x)(f))
        return await asyncio.gather(*tasks)

    async def _generate_fix(self, finding: Dict, scan_context) -> Dict:
        """
        Calls the LLM to generate a natural-language explanation and code fix.
        Uses prompt caching for the system prompt to reduce cost and latency.
        """
        cache_key = f"fix:{self._fingerprint(finding)}"
        cached = await RedisClient.get(cache_key)
        if cached:
            finding["fix_suggestion"] = cached
            return finding

        prompt = self._build_fix_prompt(finding, scan_context)

        try:
            response = await self.llm.messages.create(
                model=settings.LLM_MODEL,
                max_tokens=settings.LLM_MAX_TOKENS,
                temperature=settings.LLM_TEMPERATURE,
                system=[
                    {
                        "type": "text",
                        "text": SYSTEM_PROMPT,
                        "cache_control": {"type": "ephemeral"},  # Prompt caching
                    }
                ],
                messages=[{"role": "user", "content": prompt}],
            )
            fix_text = response.content[0].text
            finding["fix_suggestion"] = fix_text
            await RedisClient.set(cache_key, fix_text, ttl=settings.CACHE_FINDINGS_TTL)
        except Exception as exc:
            logger.error("LLM fix generation failed for %s: %s", finding.get("rule_id"), exc)
            finding["fix_suggestion"] = None

        return finding

    def _build_fix_prompt(self, finding: Dict, scan_context) -> str:
        return f"""Security finding requiring analysis and fix suggestion:

**Finding Details:**
- Rule ID: {finding.get('rule_id')}
- Severity: {finding.get('severity')}
- Language: {finding.get('language')}
- File: {finding.get('file_path')}:{finding.get('line_number')}
- Scanner: {finding.get('scanner')}
- Message: {finding.get('message')}

**Vulnerable Code Snippet:**
```{finding.get('language', '')}
{finding.get('code_snippet', 'Not available')}
```

**CVE / CWE:** {finding.get('cve_id', 'N/A')} / {finding.get('cwe_id', 'N/A')}
**CVSS Score:** {finding.get('cvss_score', 'N/A')}
**EPSS Score:** {finding.get('epss_score', 'N/A')} (probability of exploitation)

Repository: {scan_context.repo_name} | Branch: {scan_context.branch}

Please provide:
1. Plain-language explanation of the vulnerability
2. Attack scenario (how could this be exploited?)
3. Exact code fix with the corrected snippet
4. Prevention guidance to avoid recurrence
5. OWASP category if applicable"""

    # ------------------------------------------------------------------
    # Compliance mapping
    # ------------------------------------------------------------------

    COMPLIANCE_MAP = {
        "sql-injection": ["OWASP-A03", "CWE-89", "SOC2-CC6.1"],
        "xss": ["OWASP-A03", "CWE-79", "SOC2-CC6.1"],
        "hardcoded-secret": ["OWASP-A07", "CWE-798", "SOC2-CC6.2", "ISO27001-A.9"],
        "insecure-deserialization": ["OWASP-A08", "CWE-502"],
        "outdated-dependency": ["OWASP-A06", "SOC2-CC7.1"],
        "iac-misconfiguration": ["NIST-CSF-PR.AC", "SOC2-CC6.6"],
    }

    def _map_compliance(self, finding: Dict) -> Dict:
        rule_id = finding.get("rule_id", "").lower()
        for pattern, frameworks in self.COMPLIANCE_MAP.items():
            if pattern in rule_id:
                finding["compliance_frameworks"] = frameworks
                break
        else:
            finding.setdefault("compliance_frameworks", [])
        return finding

    # ------------------------------------------------------------------
    # Vector indexing
    # ------------------------------------------------------------------

    async def _index_findings(self, findings: List[Dict], scan_id: str):
        """Index findings in vector store for semantic similarity search."""
        try:
            await self.vector_client.upsert_findings(scan_id, findings)
        except Exception as exc:
            logger.warning("Vector indexing failed for scan %s: %s", scan_id, exc)

    # ------------------------------------------------------------------
    # Pipeline gate evaluation
    # ------------------------------------------------------------------

    def _evaluate_gate(self, severity_counts: Dict[str, int]) -> str:
        critical = severity_counts.get("CRITICAL", 0)
        high = severity_counts.get("HIGH", 0)
        if critical > 0 or high > settings.GATE_CVSS_BLOCK_THRESHOLD:
            return "BLOCK"
        if high > 0 or severity_counts.get("MEDIUM", 0) > 0:
            return "WARN"
        return "PASS"

    def _count_severities(self, findings: List[Dict]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "UNKNOWN")
            counts[sev] = counts.get(sev, 0) + 1
        return counts
