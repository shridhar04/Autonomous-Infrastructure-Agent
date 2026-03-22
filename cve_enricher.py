"""
CVE Enricher — Fetches vulnerability metadata from NVD, OSV, and EPSS APIs.
"""

import aiohttp
import logging
from typing import Any, Dict

from config.settings import settings
from observability.logging.logger import get_logger

logger = get_logger(__name__)


class CVEEnricher:
    """
    Enriches findings with data from:
    - NVD (National Vulnerability Database) — CVSS scores, description
    - OSV (Open Source Vulnerabilities) — package-level data
    - EPSS (Exploit Prediction Scoring System) — exploitation probability
    """

    def __init__(self):
        self._session: aiohttp.ClientSession | None = None

    async def initialize(self):
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            headers={"User-Agent": "SecureOps-AI/1.0"},
        )

    async def fetch(self, cve_id: str) -> Dict[str, Any]:
        data = {}

        nvd_data = await self._fetch_nvd(cve_id)
        data.update(nvd_data)

        epss_data = await self._fetch_epss(cve_id)
        data.update(epss_data)

        return data

    async def _fetch_nvd(self, cve_id: str) -> Dict:
        try:
            url = f"{settings.NVD_API_URL}?cveId={cve_id}"
            headers = {}
            if settings.NVD_API_KEY:
                headers["apiKey"] = settings.NVD_API_KEY

            async with self._session.get(url, headers=headers) as resp:
                if resp.status != 200:
                    return {}
                raw = await resp.json()
                vulns = raw.get("vulnerabilities", [])
                if not vulns:
                    return {}

                cve = vulns[0].get("cve", {})
                metrics = cve.get("metrics", {})
                cvss_data = (
                    metrics.get("cvssMetricV31", [{}])[0]
                    or metrics.get("cvssMetricV30", [{}])[0]
                    or {}
                )
                cvss_score = cvss_data.get("cvssData", {}).get("baseScore")
                vector = cvss_data.get("cvssData", {}).get("vectorString")

                descriptions = cve.get("descriptions", [])
                description = next(
                    (d["value"] for d in descriptions if d.get("lang") == "en"), ""
                )

                return {
                    "cvss_score": cvss_score,
                    "cvss_vector": vector,
                    "nvd_description": description,
                    "published_date": cve.get("published"),
                    "last_modified": cve.get("lastModified"),
                    "cwe_ids": [
                        w.get("description", [{}])[0].get("value")
                        for w in cve.get("weaknesses", [])
                    ],
                }
        except Exception as exc:
            logger.warning("NVD fetch failed for %s: %s", cve_id, exc)
            return {}

    async def _fetch_epss(self, cve_id: str) -> Dict:
        try:
            url = f"{settings.EPSS_API_URL}?cve={cve_id}"
            async with self._session.get(url) as resp:
                if resp.status != 200:
                    return {}
                raw = await resp.json()
                data = raw.get("data", [])
                if not data:
                    return {}
                return {
                    "epss_score": float(data[0].get("epss", 0)),
                    "epss_percentile": float(data[0].get("percentile", 0)),
                }
        except Exception as exc:
            logger.warning("EPSS fetch failed for %s: %s", cve_id, exc)
            return {}
