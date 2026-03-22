"""
Weaviate vector store client.
Indexes findings as vectors for semantic similarity search —
allows finding similar vulnerabilities across repositories.
"""

import logging
from typing import Any, Dict, List

import weaviate
from weaviate.classes.config import Property, DataType, Configure

from config.settings import settings
from observability.logging.logger import get_logger

logger = get_logger(__name__)

FINDINGS_CLASS = "SecurityFinding"


class WeaviateClient:
    _client: weaviate.WeaviateClient | None = None

    @classmethod
    async def connect(cls):
        try:
            cls._client = weaviate.connect_to_local(
                host=settings.WEAVIATE_URL.replace("http://", "").split(":")[0],
                port=int(settings.WEAVIATE_URL.split(":")[-1]),
            )
            cls._ensure_schema()
            logger.info("Weaviate connected: %s", settings.WEAVIATE_URL)
        except Exception as exc:
            logger.warning("Weaviate connection failed (non-fatal): %s", exc)

    @classmethod
    def _ensure_schema(cls):
        """Create the SecurityFinding collection if it doesn't exist."""
        if not cls._client:
            return
        if not cls._client.collections.exists(FINDINGS_CLASS):
            cls._client.collections.create(
                name=FINDINGS_CLASS,
                vectorizer_config=Configure.Vectorizer.none(),
                properties=[
                    Property(name="scan_id", data_type=DataType.TEXT),
                    Property(name="rule_id", data_type=DataType.TEXT),
                    Property(name="severity", data_type=DataType.TEXT),
                    Property(name="language", data_type=DataType.TEXT),
                    Property(name="message", data_type=DataType.TEXT),
                    Property(name="cve_id", data_type=DataType.TEXT),
                    Property(name="fingerprint", data_type=DataType.TEXT),
                ],
            )

    @classmethod
    async def upsert_findings(cls, scan_id: str, findings: List[Dict]):
        """Batch index findings into Weaviate."""
        if not cls._client:
            return
        try:
            collection = cls._client.collections.get(FINDINGS_CLASS)
            with collection.batch.dynamic() as batch:
                for f in findings:
                    batch.add_object({
                        "scan_id": scan_id,
                        "rule_id": f.get("rule_id", ""),
                        "severity": f.get("severity", ""),
                        "language": f.get("language", ""),
                        "message": f.get("message", ""),
                        "cve_id": f.get("cve_id", ""),
                        "fingerprint": f.get("fingerprint", ""),
                    })
        except Exception as exc:
            logger.warning("Weaviate upsert failed: %s", exc)

    @classmethod
    async def disconnect(cls):
        if cls._client:
            cls._client.close()
