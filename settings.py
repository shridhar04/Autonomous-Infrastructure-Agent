"""
Application configuration — loaded from environment variables.
All secrets must be provided via environment; never hardcoded.
"""

from functools import lru_cache
from typing import List
from pydantic_settings import BaseSetings

class Settings(BaseSettings):
    #App
    APP_NAME: str = "SecureOps AI"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 4
    LOG_LEVEL: str = "INFO"

    #Security
    SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_EPIRE_MINUTES: int = 60
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000"]

    #Rate Limiting
    RATE_LIMIT_RPM: int = 100

    #Database
    DATABASE_URL: str
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20

    #Redis Cache
    REDIS_URL: str = "redis://localhost:6379/0"
    CACHE_DEFAULT_TTL: int = 300        # 5 minutes
    CACHE_CVE_TTL: int = 86400          # 24 hours — CVE data changes slowly
    CACHE_FINDINGS_TTL: int = 600       # 10 minutes
    CACHE_POLICY_TTL: int = 3600        # 1 hour — policy rules rarely change

    # Vector store (Weaviate)
    WEAVIATE_URL: str = "http://localhost:8080"
    WEAVIATE_API_KEY: str = ""

    # LLM
    ANTHROPIC_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    LLM_PROVIDER: str = "anthropic"          # anthropic | openai | local
    LLM_MODEL: str = "claude-opus-4-6"
    LLM_MAX_TOKENS: int = 4096
    LLM_TEMPERATURE: float = 0.1             # Low temp for deterministic security analysis
    LLM_PROMPT_CACHE_ENABLED: bool = True    # Anthropic prompt caching

    # CVE / Vulnerability databases
    NVD_API_KEY: str = ""
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    OSV_API_URL: str = "https://api.osv.dev/v1"
    EPSS_API_URL: str = "https://api.first.org/data/v1/epss"

    # Scanner tools
    SEMGREP_RULES: str = "auto"
    SEMGREP_TIMEOUT: int = 300
    BANDIT_CONFIDENCE: str = "MEDIUM"
    GITLEAKS_CONFIG_PATH: str = "config/gitleaks.toml"
    TRIVY_SEVERITY: str = "CRITICAL,HIGH,MEDIUM"
    CHECKOV_FRAMEWORK: str = "all"

    # Notifications
    SLACK_BOT_TOKEN: str = ""
    SLACK_CHANNEL_CRITICAL: str = "#security-critical"
    SLACK_CHANNEL_GENERAL: str = "#security-alerts"
    PAGERDUTY_API_KEY: str = ""
    PAGERDUTY_SERVICE_ID: str = ""
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    ALERT_EMAIL_FROM: str = "secureops@yourorg.com"

    # Pipeline gate thresholds
    GATE_BLOCK_SEVERITY: List[str] = ["CRITICAL"]
    GATE_WARN_SEVERITY: List[str] = ["HIGH", "MEDIUM"]
    GATE_CVSS_BLOCK_THRESHOLD: float = 9.0
    GATE_EPSS_BLOCK_THRESHOLD: float = 0.7

    # OPA policy engine
    OPA_URL: str = "http://localhost:8181"
    OPA_POLICY_PATH: str = "policies/opa"

    # Compliance
    SBOM_OUTPUT_FORMAT: str = "cyclonedx"    # cyclonedx | spdx
    COMPLIANCE_FRAMEWORKS: List[str] = ["SOC2", "ISO27001", "OWASP-TOP10", "NIST-CSF"]

    # Observability
    OTEL_EXPORTER_ENDPOINT: str = "http://localhost:4317"
    PROMETHEUS_PORT: int = 9090
    GRAFANA_URL: str = "http://localhost:3001"        

    class Config:
        env_file = "config/.env"
        case_sensitive = True

@lru_cache()
def get_settings() -> Settings:
    return Settings()

settings = get_settings()      
