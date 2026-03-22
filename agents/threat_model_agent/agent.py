"""
Threat Model Agent — AI-powered STRIDE threat modeling for new features and PRs.
Reads architecture context and generates threat scenarios automatically.
"""

from typing import Any, Dict, List

from anthropic import AsyncAnthropic
from config.settings import settings
from observability.logging.logger import get_logger

logger = get_logger(__name__)

THREAT_MODEL_PROMPT = """You are a senior security architect specializing in threat modeling.
Analyze the provided system context and generate a comprehensive STRIDE threat model.

For each threat:
- Category: Spoofing | Tampering | Repudiation | Information Disclosure | DoS | Elevation of Privilege
- Description: What could go wrong
- Attack vector: How an attacker would exploit it
- Impact: Business and technical impact (High/Medium/Low)
- Mitigation: Specific, actionable countermeasures

Output as structured JSON array."""


class ThreatModelAgent:
    """
    Generates STRIDE threat models for:
    - New feature PRs (reads diff + API spec)
    - Architecture diagrams
    - Microservice definitions
    """

    def __init__(self):
        self.llm = AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)

    async def generate(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a STRIDE threat model from system context.
        context should include: component_name, api_endpoints, data_flows, trust_boundaries
        """
        logger.info("Generating threat model for: %s", context.get("component_name"))

        prompt = self._build_prompt(context)

        try:
            response = await self.llm.messages.create(
                model=settings.LLM_MODEL,
                max_tokens=2048,
                temperature=0.2,
                system=[{
                    "type": "text",
                    "text": THREAT_MODEL_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }],
                messages=[{"role": "user", "content": prompt}],
            )

            import json
            raw_text = response.content[0].text
            # Strip markdown fences if present
            clean = raw_text.replace("```json", "").replace("```", "").strip()
            threats = json.loads(clean)

            return {
                "component": context.get("component_name"),
                "threat_count": len(threats),
                "threats": threats,
                "stride_summary": self._summarize_stride(threats),
            }

        except Exception as exc:
            logger.error("Threat model generation failed: %s", exc)
            return {"component": context.get("component_name"), "threats": [], "error": str(exc)}

    def _build_prompt(self, context: Dict) -> str:
        return f"""Generate a STRIDE threat model for the following system component:

**Component:** {context.get('component_name', 'Unknown')}
**Description:** {context.get('description', 'N/A')}

**API Endpoints:**
{self._format_list(context.get('api_endpoints', []))}

**Data Flows:**
{self._format_list(context.get('data_flows', []))}

**Trust Boundaries:**
{self._format_list(context.get('trust_boundaries', []))}

**Technologies:** {', '.join(context.get('technologies', []))}

Return a JSON array of threat objects. Each object must have:
category, title, description, attack_vector, impact, likelihood, mitigation"""

    def _format_list(self, items: List) -> str:
        return "\n".join(f"- {item}" for item in items) if items else "- None specified"

    def _summarize_stride(self, threats: List[Dict]) -> Dict[str, int]:
        summary = {
            "Spoofing": 0, "Tampering": 0, "Repudiation": 0,
            "Information Disclosure": 0, "DoS": 0, "Elevation of Privilege": 0,
        }
        for t in threats:
            cat = t.get("category", "")
            if cat in summary:
                summary[cat] += 1
        return summary
