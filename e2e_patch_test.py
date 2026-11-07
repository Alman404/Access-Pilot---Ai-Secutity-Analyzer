"""End-to-end test for the patch approve/apply/verify pipeline (no Gemini needed).

Simulates a proposed patch in the database (as Gemini would produce), then
drives the real API endpoints via TestClient:
  1. approve  -> applies diff to isolated working copy (git apply)
  2. verify   -> sandbox verification. Docker-free environment here, so the
                 static-recheck strategy must be used and honestly labelled.
  3. a malicious diff with path traversal must be rejected.

Run:  python e2e_patch_test.py
"""

import difflib
import shutil
from pathlib import Path

BACKEND = Path(__file__).resolve().parent

from config import settings
from database import SessionLocal
from models import Finding, Patch, Scan
from main import app
from fastapi.testclient import TestClient

REPO_CONTENT = """import subprocess


def run_command(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True)
"""

FIXED_CONTENT = """import subprocess


def run_command(cmd):
    \"\"\"Run a command without spawning a shell (fixes command injection).\"\"\"
    if isinstance(cmd, str):
        from shlex import split
        cmd = split(cmd)
    return subprocess.run(cmd, shell=False, capture_output=True)
"""

patch_diff = "\n".join(
    difflib.unified_diff(
        REPO_CONTENT.splitlines(),
        FIXED_CONTENT.splitlines(),
        fromfile="a/service.py",
        tofile="b/service.py",
        lineterm="",
    )
) + "\n"

EVIL_DIFF = patch_diff.replace("b/service.py", "b/../../evil.py")


def main() -> None:
    settings.workspace_dir.mkdir(parents=True, exist_ok=True)
    scan_id = "e2e" + __import__("uuid").uuid4().hex[:20]
    clone_dir = settings.workspace_dir / "scans" / scan_id / "repo"
    clone_dir.mkdir(parents=True)
    (clone_dir / "service.py").write_text(REPO_CONTENT, encoding="utf-8")

    db = SessionLocal()
    scan = Scan(id=scan_id, repo_url="https://github.com/example/sample",
                repo_name="sample", status="completed")
    db.add(scan)
    finding = Finding(
        scan_id=scan_id, title="Command injection via shell=True",
        severity="high", category="Command Injection",
        file_path="service.py", line_number=5,
        evidence="subprocess.run(cmd, shell=True, ...)",
        recommendation="Do not use shell=True with external input.",
        scanner="semgrep",
        rule_id="python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
    )
    db.add(finding)
    db.commit()
    patch = Patch(finding_id=finding.id, proposed_diff=patch_diff,
                  explanation="Replace shell=True with shell=False + shlex.",
                  status="proposed")
    db.add(patch)
    db.commit()
    patch_id, finding_id = patch.id, finding.id
    db.close()
    print("seeded scan:", scan_id, "patch id:", patch_id, "finding id:", finding_id)

    with TestClient(app) as client:
        # 1. approve -> apply to working copy
        r = client.post(f"/approve-patch/{patch_id}")
        print("approve:", r.status_code, r.json().get("status"))
        assert r.status_code == 200, r.text

        work = settings.workspace_dir / "scans" / scan_id / "work" / "service.py"
        assert work.is_file(), "patched working copy missing"
        assert "shell=False" in work.read_text(encoding="utf-8"), "patch not applied"
        print("working copy patched OK")

        # 2. verify (no Docker on this machine -> expect static-recheck)
        r = client.post(f"/verify/{patch_id}")
        body = r.json()
        print("verify:", r.status_code, body.get("status"),
              "| strategy:", (body.get("verification_result") or {}).get("strategy"),
              "| reason:", ((body.get("verification_result") or {}).get("reason") or "")[:80])
        assert r.status_code == 200
        assert body.get("status") == "verified", body
        assert (body.get("verification_result") or {}).get("strategy") == "static-recheck"

        # 3. ensure GitHub untouched / pristine clone preserved
        assert "shell=True" in (clone_dir / "service.py").read_text(encoding="utf-8"), \
            "pristine clone must remain unmodified"
        print("pristine clone intact OK")

        # 4. path traversal diff must be rejected
        db = SessionLocal()
        patch2 = Patch(finding_id=finding_id, proposed_diff=EVIL_DIFF, status="proposed")
        db.add(patch2)
        db.commit()
        patch2_id = patch2.id
        db.close()
        r = client.post(f"/approve-patch/{patch2_id}")
        print("evil diff approve:", r.status_code, (r.json().get("detail") or "")[:90])
        assert r.status_code == 422, r.text

        # 5. double-approve must be refused 409
        r = client.post(f"/approve-patch/{patch_id}")
        print("re-approve:", r.status_code, "expected 409")
        assert r.status_code == 409, r.text

    print("\nALL E2E PATCH TESTS PASSED")


if __name__ == "__main__":
    main()
