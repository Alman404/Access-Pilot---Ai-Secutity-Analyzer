"""AccessPilot — FastAPI backend.

Endpoints are logged without ever printing secret values, evidence bodies or
API keys; log lines reference ids/paths only.
"""

import json
import logging
import shutil
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

import ai_engine
import patcher
import sandbox
import scanner
from config import settings
from database import SessionLocal, engine, get_db, init_db
from models import Finding, Patch, Scan, new_scan_id, utcnow
from schemas import (
    FindingOut,
    HealthOut,
    InvestigationOut,
    PatchActionOut,
    PatchCreated,
    PatchOut,
    ReportOut,
    ScanCreated,
    ScanDetail,
    ScanStatus,
    ScanSummaryItem,
)
import uvicorn

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("accesspilot")

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="Find it. Prove it. Fix it. Verify it.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    init_db()
    # Crash recovery: a scan's work runs in a worker thread, so any scan still
    # marked pending/scanning at boot belongs to a previous (dead) process.
    # Mark it failed honestly instead of leaving an eternal "scanning" state.
    from database import SessionLocal
    from models import Scan

    db = SessionLocal()
    try:
        stale = db.query(Scan).filter(Scan.status.in_(["pending", "scanning"])).all()
        for s in stale:
            s.status = "failed"
            s.error = (
                "Scan interrupted: the backend was restarted while this scan was "
                "running. Start a new scan."
            )
        if stale:
            db.commit()
    finally:
        db.close()


def error(code: int, message: str) -> HTTPException:
    return HTTPException(status_code=code, detail=message)


# --------------------------------------------------------------------------- #
# Status / health
# --------------------------------------------------------------------------- #


@app.get("/", tags=["meta"])
def root():
    return {
        "app": settings.app_name,
        "tagline": "Find it. Prove it. Fix it. Verify it.",
        "version": settings.version,
        "docs": "/docs",
        "endpoints": [
            "GET /health", "POST /scan", "GET /scan/{scan_id}", "GET /scans",
            "POST /investigate/{finding_id}", "POST /generate-patch/{finding_id}",
            "POST /approve-patch/{patch_id}", "POST /verify/{patch_id}",
            "GET /report/{scan_id}",
        ],
    }


@app.get("/health", response_model=HealthOut, tags=["meta"])
def health(db: Session = Depends(get_db)):
    db_status = "connected"
    try:
        db.execute(select(Scan.id).limit(1))
    except Exception:  # noqa: BLE001
        db_status = "error"
    scanner_availability = {
        "gitleaks": "available" if scanner.tool_available("gitleaks") else "not installed (scans skipped, reported honestly)",
        "semgrep": "available" if scanner.tool_available("semgrep") else "not installed (scans skipped, reported honestly)",
        "pip-audit": "available" if scanner.tool_available("pip-audit") else "not installed (scans skipped, reported honestly)",
    }
    return HealthOut(
        status="ok" if db_status == "connected" else "degraded",
        app=settings.app_name,
        version=settings.version,
        database=db_status,
        gemini=ai_engine.status_snapshot(),
        docker=sandbox.docker_status(),
        scanners=scanner_availability,
    )


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #


class ScanRequest(BaseModel):
    repo_url: str


@app.post("/scan", response_model=ScanCreated, status_code=202, tags=["scan"])
def create_scan(req: ScanRequest, background: BackgroundTasks,
                db: Session = Depends(get_db)):
    try:
        canonical, _owner, repo = scanner.validate_github_url(req.repo_url)
    except ValueError as exc:
        raise error(400, str(exc))

    scan = Scan(id=new_scan_id(), repo_url=canonical, repo_name=repo, status="pending")
    db.add(scan)
    db.commit()

    background.add_task(_run_scan_background, scan.id, canonical)
    log.info("scan scheduled id=%s repo=%s", scan.id, repo)
    return ScanCreated(
        scan_id=scan.id, status=scan.status,
        message="Scan scheduled. Poll GET /scan/{scan_id} for progress.",
    )


def _run_scan_background(scan_id: str, url: str) -> None:
    scanner_infos: list[dict] = []
    try:
        db = SessionLocal()
        scan = db.get(Scan, scan_id)
        if not scan:
            return
        scan.status = "scanning"
        db.commit()

        scan_dir = settings.workspace_dir / "scans" / scan_id
        clone_dir = scanner.clone_repo(url, scan_dir)
        findings, scanner_infos = scanner.scan_repository(clone_dir)

        for f in findings:
            db.add(Finding(scan_id=scan_id, **f))
        scan.status = "completed"
        scan.finished_at = utcnow()
        scan.scanner_info = json.dumps(scanner_infos)
        db.commit()
        log.info("scan completed id=%s findings=%d", scan_id, len(findings))
    except Exception as exc:  # noqa: BLE001
        log.info("scan failed id=%s reason=%s", scan_id, (str(exc) or type(exc).__name__)[:300])
        db2 = SessionLocal()
        try:
            s = db2.get(Scan, scan_id)
            if s:
                s.status = "failed"
                s.error = (str(exc) or type(exc).__name__)[:1000]
                s.scanner_info = json.dumps(scanner_infos)
                s.finished_at = utcnow()
                db2.commit()
        finally:
            db2.close()
        _cleanup_scan(scan_id)
    finally:
        try:
            db.close()
        except Exception:  # noqa: BLE001
            pass


def _cleanup_scan(scan_id: str) -> None:
    """Delete temp clones/logs for failed scans; keep nothing stale on disk."""
    scan_dir = settings.workspace_dir / "scans" / scan_id
    shutil.rmtree(scan_dir, ignore_errors=True)


def _summary(findings: list[Finding]) -> dict:
    counts = {"total": len(findings)}
    for sev in ("critical", "high", "medium", "low"):
        counts[sev] = sum(1 for f in findings if f.severity == sev)
    counts["fixed_verified"] = 0
    return counts


@app.get("/scan/{scan_id}", response_model=ScanDetail, tags=["scan"])
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise error(404, "Scan not found.")
    findings = db.scalars(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id)
    ).all()
    patch_by_finding = {p.finding_id: p for p in db.scalars(select(Patch))}
    out = ScanDetail(
        id=scan.id, repo_url=scan.repo_url, repo_name=scan.repo_name,
        status=scan.status, created_at=scan.created_at,
        finished_at=scan.finished_at, error=scan.error,
        scanner_info=json.loads(scan.scanner_info) if scan.scanner_info else None,
        summary=_summary(findings),
        findings=[_finding_out(f, patch_by_finding.get(f.id)) for f in findings],
    )
    return out


def _finding_out(f: Finding, patch: Patch | None) -> FindingOut:
    fo = FindingOut(
        id=f.id, scan_id=f.scan_id, title=f.title, severity=f.severity,
        category=f.category, description=f.description, file_path=f.file_path,
        line_number=f.line_number, evidence=f.evidence,
        recommendation=f.recommendation, ai_analysis=f.ai_analysis,
        scanner=f.scanner, rule_id=f.rule_id, created_at=f.created_at,
        patch=_patch_out(patch) if patch else None,
    )
    return fo


def _patch_out(p: Patch) -> PatchOut:
    return PatchOut(
        id=p.id, finding_id=p.finding_id, proposed_diff=p.proposed_diff,
        explanation=p.explanation,
        expected_changes=json.loads(p.expected_changes or "[]"),
        side_effects=json.loads(p.side_effects or "[]"),
        status=p.status,
        verification_result=json.loads(p.verification_result) if p.verification_result else None,
        created_at=p.created_at,
    )


@app.get("/scans", response_model=list[ScanSummaryItem], tags=["scan"])
def list_scans(db: Session = Depends(get_db)):
    scans = db.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(50)).all()
    out = []
    for s in scans:
        findings = db.scalars(select(Finding).where(Finding.scan_id == s.id)).all()
        out.append(ScanSummaryItem(
            id=s.id, repo_url=s.repo_url, repo_name=s.repo_name, status=s.status,
            created_at=s.created_at, finished_at=s.finished_at, error=s.error,
            finding_count=len(findings),
            critical_count=sum(1 for f in findings if f.severity == "critical"),
            high_count=sum(1 for f in findings if f.severity == "high"),
        ))
    return out


# --------------------------------------------------------------------------- #
# AI investigation / patch generation
# --------------------------------------------------------------------------- #


def _get_finding(db: Session, finding_id: int) -> Finding:
    f = db.get(Finding, finding_id)
    if not f:
        raise error(404, f"Finding {finding_id} not found.")
    f_dict = {
        "title": f.title, "severity": f.severity, "category": f.category,
        "description": f.description, "file_path": f.file_path,
        "line_number": f.line_number, "evidence": f.evidence,
        "recommendation": f.recommendation, "scanner": f.scanner,
        "rule_id": f.rule_id,
    }
    return f, f_dict


def _scan_clone_path(scan_id: str) -> Path:
    clone = settings.workspace_dir / "scans" / scan_id / "repo"
    if not clone.is_dir():
        raise error(409,
                    "The cloned repository for this scan is no longer available "
                    "(it may have been cleaned up). Please rescan the repository.")
    return clone


@app.post("/investigate/{finding_id}", response_model=InvestigationOut, tags=["ai"])
def investigate(finding_id: int, db: Session = Depends(get_db)):
    f, f_dict = _get_finding(db, finding_id)
    try:
        res = ai_engine.investigate(f_dict)
    except ai_engine.AIUnavailable as exc:
        raise error(503, str(exc))
    f.ai_analysis = res["ai_analysis"]
    db.commit()
    res["finding_id"] = f.id
    res["model"] = ai_engine.model_name()
    return InvestigationOut(**res)


@app.post("/generate-patch/{finding_id}", response_model=PatchCreated, tags=["ai"])
def generate_patch(finding_id: int, db: Session = Depends(get_db)):
    f, f_dict = _get_finding(db, finding_id)
    clone = _scan_clone_path(f.scan_id)
    try:
        res = ai_engine.generate_patch(f_dict, clone)
    except ai_engine.AIUnavailable as exc:
        raise error(503, str(exc))
    patch = Patch(
        finding_id=f.id, proposed_diff=res["unified_diff"],
        explanation=res["explanation"] or None,
        expected_changes=json.dumps(res["expected_changes"]),
        side_effects=json.dumps(res["side_effects"]),
        status="proposed",
    )
    db.add(patch)
    db.commit()
    log.info("patch proposed id=%d finding=%d", patch.id, f.id)
    return PatchCreated(
        id=patch.id, finding_id=patch.finding_id, status=patch.status,
        proposed_diff=patch.proposed_diff, explanation=res["explanation"],
        expected_changes=res["expected_changes"], side_effects=res["side_effects"],
        message="Patch proposed. Nothing has been applied yet — review it and "
                "approve explicitly to apply it to an isolated working copy.",
    )


# --------------------------------------------------------------------------- #
# Patch approval / verification
# --------------------------------------------------------------------------- #


@app.post("/approve-patch/{patch_id}", response_model=PatchActionOut, tags=["patch"])
def approve_patch(patch_id: int, db: Session = Depends(get_db)):
    patch = db.get(Patch, patch_id)
    if not patch:
        raise error(404, f"Patch {patch_id} not found.")
    if patch.status != "proposed":
        raise error(409,
                    f"Patch is in status '{patch.status}'. Only a freshly proposed "
                    "patch can be approved.")
    finding = db.get(Finding, patch.finding_id)
    if not finding:
        raise error(404, "The finding tied to this patch no longer exists.")
    clone = _scan_clone_path(finding.scan_id)

    try:
        patcher.apply_patched_diff(finding.scan_id, patch.proposed_diff, clone)
    except ValueError as exc:
        patch.status = "apply_failed"
        db.commit()
        raise error(422, f"Patch rejected: {exc}")

    patch.status = "approved"
    db.commit()
    log.info("patch approved id=%d (applied to isolated working copy only)", patch.id)
    return PatchActionOut(
        id=patch.id, status=patch.status,
        message="Patch approved and applied to the isolated working copy only. "
                "Your GitHub repository was NOT modified. Now run verification.",
    )


@app.post("/verify/{patch_id}", response_model=PatchActionOut, tags=["patch"])
def verify_patch(patch_id: int, db: Session = Depends(get_db)):
    patch = db.get(Patch, patch_id)
    if not patch:
        raise error(404, f"Patch {patch_id} not found.")
    if patch.status not in ("approved", "verifying"):
        raise error(409,
                    f"Patch is in status '{patch.status}'. Apply (approve) it first.")
    finding = db.get(Finding, patch.finding_id)
    if not finding:
        raise error(404, "The finding tied to this patch no longer exists.")

    workdir = patcher.workdir_for(finding.scan_id)
    patch.status = "verifying"
    patch.verification_result = None
    db.commit()

    result = sandbox.run_verification(patch.id, workdir, {
        "file_path": finding.file_path, "rule_id": finding.rule_id,
        "title": finding.title, "severity": finding.severity,
        "category": finding.category, "scanner": finding.scanner,
    })

    final_status = {
        "verified": "verified",
        "failed": "verification_failed",
        "unavailable": "verification_unavailable",
    }[result["status"]]
    patch.status = final_status
    patch.verification_result = json.dumps(result)
    db.commit()
    log.info("verification id=%d outcome=%s strategy=%s", patch.id,
             result["status"], result.get("strategy"))

    # Optional AI commentary — never decides the outcome.
    ai_note = None
    if ai_engine.settings.gemini_configured:
        try:
            ai_note = ai_engine.explain_verification(
                result, {"title": finding.title, "severity": finding.severity,
                         "category": finding.category, "evidence": finding.evidence,
                         "file_path": finding.file_path, "line_number": finding.line_number,
                         "rule_id": finding.rule_id, "scanner": finding.scanner}
            )
        except ai_engine.AIUnavailable:
            ai_note = None
    if ai_note:
        result = dict(result)
        result["ai_commentary"] = ai_note

    patch.verification_result = json.dumps(result)
    db.commit()
    return PatchActionOut(id=patch.id, status=patch.status,
                          message=_verif_message(result["status"]),
                          verification_result=result)


def _verif_message(status: str) -> str:
    return {
        "verified": "Verification PASSED: actual checks ran and confirmed the patch.",
        "failed": "Verification FAILED: actual checks ran and did not pass.",
        "unavailable": "Verification UNAVAILABLE: no verification engine could run "
                       "(see details). Nothing claims the issue is fixed.",
    }[status]


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #


@app.get("/report/{scan_id}", response_model=ReportOut, tags=["meta"])
def report(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise error(404, "Scan not found.")
    findings = db.scalars(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id)
    ).all()
    patch_by_finding: dict[int, Patch] = {}
    if findings:
        patches = db.scalars(select(Patch).where(Patch.finding_id.in_([f.id for f in findings]))).all()
        patch_by_finding = {p.finding_id: p for p in patches}
    fixed = sum(1 for p in patch_by_finding.values() if p.status == "verified")
    summary = _summary(findings)
    summary["fixed_verified"] = fixed
    scanner_info = json.loads(scan.scanner_info) if scan.scanner_info else None
    reports = ReportOut(
        scan=ScanStatus(
            id=scan.id, repo_url=scan.repo_url, repo_name=scan.repo_name,
            status=scan.status, created_at=scan.created_at,
            finished_at=scan.finished_at, error=scan.error,
        ),
        summary=summary,
        scanner_info=scanner_info,
        findings=[_finding_out(f, patch_by_finding.get(f.id)) for f in findings],
        generated_at=utcnow(),
    )
    return reports


# --------------------------------------------------------------------------- #
# Never crash on unexpected errors without a JSON body
# --------------------------------------------------------------------------- #


@app.exception_handler(Exception)
async def unhandled(_, exc: Exception):
    log.info("unhandled error type=%s", type(exc).__name__)
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
