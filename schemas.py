"""Pydantic schemas for API responses."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel as Base


class ScanStatus(Base):
    id: str
    repo_url: str
    repo_name: Optional[str] = None
    status: str
    created_at: datetime
    finished_at: Optional[datetime] = None
    error: Optional[str] = None


class FindingOut(Base):
    id: int
    scan_id: str
    title: str
    severity: str
    category: str
    description: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    ai_analysis: Optional[str] = None
    scanner: Optional[str] = None
    rule_id: Optional[str] = None
    created_at: datetime
    patch: Optional["PatchOut"] = None


class PatchOut(Base):
    id: int
    finding_id: int
    proposed_diff: str
    explanation: Optional[str] = None
    expected_changes: Optional[list[str]] = None
    side_effects: Optional[list[str]] = None
    status: str
    verification_result: Optional[dict] = None
    created_at: datetime


FindingOut.model_rebuild()


class ScanDetail(ScanStatus):
    findings: list[FindingOut] = []
    summary: dict = {}
    scanner_info: Optional[list[dict]] = None


class ScanSummaryItem(ScanStatus):
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0


class ScanCreated(Base):
    scan_id: str
    status: str
    message: str


class InvestigationOut(Base):
    finding_id: int
    summary: str
    why_dangerous: str
    exploitation: str
    impact: str
    remediation: str
    confidence: str
    ai_analysis: str
    model: str


class PatchCreated(Base):
    id: int
    finding_id: int
    status: str
    proposed_diff: str
    explanation: Optional[str] = None
    expected_changes: list[str] = []
    side_effects: list[str] = []
    message: str


class PatchActionOut(Base):
    id: int
    status: str
    message: str
    verification_result: Optional[dict] = None


class HealthOut(Base):
    status: str
    app: str
    version: str
    database: str
    gemini: dict
    docker: dict
    scanners: dict


class ReportOut(Base):
    scan: ScanStatus
    summary: dict
    scanner_info: Optional[list[dict]] = None
    findings: list[FindingOut] = []
    generated_at: datetime
