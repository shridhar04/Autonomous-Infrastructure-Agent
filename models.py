"""
SQLAlchemy ORM models for SecureOps AI.
Uses PostgreSQL + TimescaleDB for time-series analytics on findings.
"""

import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime,
    ForeignKey, Text, JSON, Index
)
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    pass


class Repository(Base):
    __tablename__ = "repositories"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False, unique=True)
    url = Column(String(500), nullable=False)
    default_branch = Column(String(100), default="main")
    languages = Column(ARRAY(String), default=[])
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    scans = relationship("Scan", back_populates="repository")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=False)
    branch = Column(String(255), nullable=False)
    commit_sha = Column(String(40), nullable=False)
    scan_type = Column(String(50), nullable=False)
    status = Column(String(50), default="pending")   # pending | running | complete | failed
    triggered_by = Column(String(100))
    pr_number = Column(String(20), nullable=True)
    gate_decision = Column(String(10))               # BLOCK | WARN | PASS
    total_findings = Column(Integer, default=0)
    severity_counts = Column(JSON, default={})
    duration_ms = Column(Integer)
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True))

    repository = relationship("Repository", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")

    __table_args__ = (
        Index("idx_scans_repo_commit", "repository_id", "commit_sha"),
        Index("idx_scans_started_at", "started_at"),
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    fingerprint = Column(String(32), nullable=False)
    scanner = Column(String(50), nullable=False)
    rule_id = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False)
    language = Column(String(50))
    file_path = Column(String(1000))
    line_number = Column(Integer)
    message = Column(Text)
    code_snippet = Column(Text)
    cve_id = Column(String(30))
    cwe_id = Column(String(30))
    cvss_score = Column(Float)
    epss_score = Column(Float)
    fix_suggestion = Column(Text)
    compliance_frameworks = Column(ARRAY(String), default=[])
    reported_by = Column(ARRAY(String), default=[])
    is_false_positive = Column(Boolean, default=False)
    is_accepted_risk = Column(Boolean, default=False)
    resolved_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="findings")
    feedback = relationship("FindingFeedback", back_populates="finding")

    __table_args__ = (
        Index("idx_findings_fingerprint", "fingerprint"),
        Index("idx_findings_severity", "severity"),
        Index("idx_findings_cve", "cve_id"),
    )


class FindingFeedback(Base):
    """
    Stores developer feedback on AI findings — used for model fine-tuning.
    """
    __tablename__ = "finding_feedback"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"), nullable=False)
    user_id = Column(String(100))
    action = Column(String(50))     # accepted_fix | rejected_fix | false_positive | accepted_risk
    comment = Column(Text)
    fix_applied = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    finding = relationship("Finding", back_populates="feedback")


class PolicyException(Base):
    """
    Tracks approved exceptions to security policy (e.g., CISO-approved waivers).
    """
    __tablename__ = "policy_exceptions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_fingerprint = Column(String(32), nullable=False)
    reason = Column(Text, nullable=False)
    approved_by = Column(String(100), nullable=False)
    expires_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
