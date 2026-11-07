"""Database models: Scan, Finding, Patch."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)

from database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_scan_id() -> str:
    return uuid.uuid4().hex


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(32), primary_key=True, default=new_scan_id)
    repo_url = Column(String(512), nullable=False)
    repo_name = Column(String(256), nullable=True)
    status = Column(String(32), default="pending", nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    error = Column(Text, nullable=True)
    scanner_info = Column(Text, nullable=True)  # JSON: per-scanner availability/errors


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(32), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(512), nullable=False)
    severity = Column(String(16), nullable=False)   # critical | high | medium | low
    category = Column(String(64), nullable=False)   # Secrets | SQL Injection | Dependencies | ...
    description = Column(Text, nullable=True)
    file_path = Column(String(512), nullable=True)
    line_number = Column(Integer, nullable=True)
    evidence = Column(Text, nullable=True)          # always redacted before storage
    recommendation = Column(Text, nullable=True)
    ai_analysis = Column(Text, nullable=True)       # filled by /investigate
    scanner = Column(String(32), nullable=True)     # gitleaks | semgrep | pip-audit
    rule_id = Column(String(256), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class Patch(Base):
    __tablename__ = "patches"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    proposed_diff = Column(Text, nullable=False)
    explanation = Column(Text, nullable=True)
    expected_changes = Column(Text, nullable=True)   # JSON list -> text
    side_effects = Column(Text, nullable=True)       # JSON list -> text
    status = Column(String(32), default="proposed", nullable=False, index=True)
    # proposed | approved (applied to working copy) | apply_failed | verifying
    # | verified | verification_failed | verification_unavailable
    verification_result = Column(Text, nullable=True)  # JSON: real sandbox outcome
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
