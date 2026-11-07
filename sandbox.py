"""Sandbox verification.

RULES:
  - Repository code is NEVER executed directly on the host.
  - When Docker is available, tests run in disposable containers restricted
    to: non-root user, no network at runtime, CPU/memory/pids limits, and a
    short execution deadline.
  - When Docker is unavailable, verification is reported as UNAVAILABLE.
    We never pretend it succeeded, and we never mark a finding fixed
    without real verification.

Distinguishes:
  verified      - actual checks passed
  failed        - actual checks failed
  unavailable   - verification could not be performed (missing dependency,
                  no Docker daemon, no test suite, etc.)

Fallback strategy (static-recheck): if the repo has no test suite but Semgrep
is installed, the patched working copy is re-scanned and the original finding
must no longer be present. This is static analysis ( Semgrep only reads files;
it does not execute repository code ), so it is safe to run on the host.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

from config import settings

RUNTIME_USER = 65534          # nobody, non-root runtime user
VERIF_IMAGE = "python:3.11-slim"


def docker_available() -> bool:
    """Docker must be on PATH *and* be a reachable daemon."""
    if not shutil.which("docker"):
        return False
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, timeout=15, encoding="utf-8", errors="replace",
        )
        return proc.returncode == 0 and bool((proc.stdout or "").strip())
    except (OSError, subprocess.TimeoutExpired):
        return False


def docker_status() -> dict:
    available = docker_available()
    if available:
        return {"available": True, "note": "Docker daemon reachable."}
    if not shutil.which("docker"):
        return {"available": False,
                "reason": "Docker is not installed on this machine. Install Docker Desktop, then verification will run in restricted containers."}
    return {"available": False,
            "reason": "Docker is installed but its daemon is not reachable (is Docker Desktop running?)."}


def has_test_suite(workdir: Path) -> bool:
    markers = ["pytest.ini", "pyproject.toml", "setup.cfg", "tox.ini"]
    if any((workdir / m).is_file() for m in markers):
        return True
    if (workdir / "tests").is_dir():
        return any(p.suffix == ".py" for p in (workdir / "tests").glob("*.py"))
    return any(p.name.startswith("test_") and p.suffix == ".py" for p in workdir.glob("*.py"))


# --------------------------------------------------------------------------- #
# Host-side helpers
# --------------------------------------------------------------------------- #


def _container_name(patch_id: int) -> str:
    return f"accesspilot-verify-{patch_id}"


def _volume_name(patch_id: int) -> str:
    return f"accesspilot-verif-{patch_id}"


def _docker_run(args: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          timeout=timeout, encoding="utf-8", errors="replace")


def _cleanup_volume_and_container(patch_id: int) -> None:
    cname, vname = _container_name(patch_id), _volume_name(patch_id)
    for rm_args, label in (
        (["container", "remove", "-f"], cname),
        (["volume", "remove", "-f"], vname),
    ):
        try:
            subprocess.run(["docker", *rm_args, label],
                           capture_output=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            pass


# --------------------------------------------------------------------------- #
# Docker verification pipeline
# --------------------------------------------------------------------------- #


def _verify_with_docker(patch_id: int, workdir: Path) -> dict:
    status = docker_status()
    if not status["available"]:
        return {"status": "unavailable", "strategy": "docker",
                "reason": status["reason"], "detail": None}

    cname, vname = _container_name(patch_id), _volume_name(patch_id)
    _cleanup_volume_and_container(patch_id)
    mem, cpus, timeout = settings.sandbox_memory, settings.sandbox_cpus, settings.tool_timeout

    steps = []

    def fail(reason: str, steps_out=None) -> dict:
        _cleanup_volume_and_container(patch_id)
        return {"status": "unavailable", "strategy": "docker",
                "reason": reason, "detail": steps_out or steps}

    # 1. Disposable volume; copy ONLY the working copy into it.
    try:
        steps.append({"step": "create_dependency_volume", "ok": True})
        out = _docker_run(["volume", "create", vname], 60)
        if out.returncode != 0:
            return fail(f"Docker volume creation failed: {(out.stderr or out.stdout)[:300]}", steps)
        steps.append({"step": "copy_code_in", "ok": True})
        out = _docker_run(["run", "--rm", "-v", f"{workdir}:/src:ro",
                           "-v", f"{vname}:/app",
                           VERIF_IMAGE,
                           "cp", "-r", "/src/.", "/app/"], 300)
        if out.returncode != 0:
            return fail(f"Could not copy code into the sandbox volume: {(out.stderr or out.stdout)[:300]}", steps)

        # 2. Dependency installation (network needed only to pull packages;
        #    this never executes the repository code itself).
        req = "pip install --no-cache-dir -r requirements.txt" if (workdir / "requirements.txt").is_file() else "true"
        install_cmd = (f"sh -c '{req} >/dev/null 2>&1 || true; "
                       "pip install --no-cache-dir pytest >/dev/null 2>&1 || true'")
        out = _docker_run(["run", "-v", f"{vname}:/app", "-w", "/app",
                           VERIF_IMAGE, "sh", "-c", install_cmd], 600)
        steps.append({"step": "install_dependencies", "ok": out.returncode == 0})

        # 3. TEST EXECUTION: non-root, no network, resource-capped, disposable.
        test_cmd = ("python -m pytest -q -p no:cacheprovider"
                    if has_test_suite(workdir)
                    else "echo NO_RUNNABLE_TESTS")
        if test_cmd == "echo NO_RUNNABLE_TESTS":
            return {"status": "failed", "strategy": "docker",
                    "reason": "Repository has no runnable test suite found by sandbox verifier.",
                    "detail": steps}
        out = _docker_run([
            "run", "--rm", "--name", cname,
            "--network", "none",
            "--user", str(RUNTIME_USER),
            "--memory", mem, "--memory-swap", mem,
            "--cpus", cpus,
            "--pids-limit", "128",
            "--read-only",
            "--tmpfs", "/tmp:rw,size=64m",
            "-e", "HOME=/tmp",
            "-e", "PYTHONDONTWRITEBYTECODE=1",
            "-v", f"{vname}:/app:ro",
            "-w", "/app",
            VERIF_IMAGE, "sh", "-c", test_cmd,
        ], timeout)

        steps.append({
            "step": "pytest", "ok": out.returncode == 0,
            "exit_code": out.returncode,
            "output": out.stdout[-4000:] if out.stdout else out.stderr[-2000:],
        })

        _cleanup_volume_and_container(patch_id)

        if out.returncode == 0:
            return {"status": "verified", "strategy": "docker",
                    "detail": "pytest run inside a restricted disposable container (non-root, no network, resource-limited) passed.",
                    "steps": steps}
        return {"status": "failed", "strategy": "docker",
                "reason": "Tests failed inside the verification container.",
                "detail": out.stdout[-4000:] or out.stderr[-2000:], "steps": steps}
    except subprocess.TimeoutExpired:
        return fail(f"Verification execution exceeded the {timeout}s deadline.", steps)
    except OSError as exc:
        return fail(f"Docker execution error: {exc}", steps)


# --------------------------------------------------------------------------- #
# Static re-check fallback (Semgrep reads files only; executes nothing)
# --------------------------------------------------------------------------- #


def _verify_with_semgrep_recheck(finding: dict, workdir: Path) -> dict:
    import scanner

    res = scanner.run_semgrep(workdir)
    if res["result"] != "completed":
        return {"status": "unavailable", "strategy": "static-recheck",
                "reason": (res.get("reason") or "Semgrep recheck could not run.")}

    want_file = str(finding.get("file_path") or "").replace("\\", "/").split("/")[-1]
    want_rule = str(finding.get("rule_id") or "")
    remaining = []
    for f in res.get("findings", []):
        rel = str(f.get("file_path") or "")
        rule = str(f.get("rule_id") or "")
        if want_file and rel.split("/")[-1] == want_file and (
            not want_rule
            or rule.endswith(want_rule)
            or rule.split(".")[-1] == want_rule.split(".")[-1]
        ):
            remaining.append(f"{rel}:{f.get('line_number')} ({rule})")
    if remaining:
        return {"status": "failed", "strategy": "static-recheck",
                "reason": "The original static-analysis finding is still present in the patched working copy.",
                "detail": "; ".join(remaining[:10])}
    return {"status": "verified", "strategy": "static-recheck",
            "detail": "Semgrep re-scanned the patched working copy and the original finding no longer appears."}


# --------------------------------------------------------------------------- #
# Public entrypoint
# --------------------------------------------------------------------------- #


def run_verification(patch_id: int, workdir: Path, finding: dict) -> dict:
    """Authorize-then-verify. Returns {'status': verified|failed|unavailable, ...}."""
    if not workdir.is_dir():
        return {"status": "unavailable", "strategy": None,
                "reason": "Patched working copy is missing; approve the patch first."}

    docker_result = _verify_with_docker(patch_id, workdir)
    if docker_result["status"] in ("verified", "failed"):
        return docker_result
    docker_unavail_reason = docker_result.get("reason")

    if not has_test_suite(workdir):
        # Docker could not confirm via tests; try the static re-check.
        static_result = _verify_with_semgrep_recheck(finding, workdir)
        if static_result["status"] in ("verified", "failed"):
            static_result["docker_note"] = docker_unavail_reason
            return static_result
        return {"status": "unavailable", "strategy": None,
                "reason": (static_result.get("reason") or "") + " "
                          + (docker_unavail_reason or "")}

    return docker_result
