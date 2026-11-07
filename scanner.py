"""Real security scanners: Gitleaks (secrets), Semgrep (SAST), pip-audit (deps).

Rules:
 - Parse real tool output only. No synthetic findings, ever.
 - Tools that are missing or fail are reported as skipped/unavailable.
 - All secret material is redacted before it is stored, sent to Gemini,
   returned to the frontend, or written to logs.
"""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from config import settings

# Directory (suffix) patterns we never want to analyze.
IGNORED_DIR_PARTS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
    ".eggs", "site-packages", ".idea", ".vscode",
}


# --------------------------------------------------------------------------- #
# Secret redaction
# --------------------------------------------------------------------------- #

_SECRET_PATTERNS = [
    # Cloud / SaaS provider keys
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"AIza[A-Za-z0-9_-]{30,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+"),  # JWT
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----.*?-----END(?: [A-Z ]+)?PRIVATE KEY(?: BLOCK)?-----", re.DOTALL),
    # key=value style secrets (long values, any quote style)
    re.compile(
        r"(?i)\b((?:api[_-]?key|secret|token|password|passwd|pwd|authorization|bearer)\s*[=:]\s*['\"]?)"
        r"([A-Za-z0-9_\-./+!#$%^&*]{12,})(['\"]?)"
    ),
]

_KV_SECRET = _SECRET_PATTERNS[-1]  # the key=value pattern
REDACTED = "[REDACTED]"

# Generic very-long-token redaction is applied in a final pass; path-like
# strings (containing "." or ":") are preserved so evidence/file paths survive.
_GENERIC_TOKEN_RE = re.compile(r"\b[A-Za-z0-9+/=]{40,}\b")


def _redact_kv(m) -> str:
    return f"{m.group(1)}{REDACTED}{m.group(3) or ''}"


def redact_text(text: str) -> str:
    """Scrub secret-looking material out of arbitrary text (best effort)."""
    if not text:
        return text
    out = text
    for pat in _SECRET_PATTERNS:
        if pat is _KV_SECRET:
            out = pat.sub(_redact_kv, out)
        else:
            out = pat.sub(REDACTED, out)

    def _blob(m) -> str:
        s = m.group(0)
        return s if ("." in s or ":" in s or "/" in s) else REDACTED

    # Final pass: long unbroken random-looking strings. File paths (contain
    # '.', ':' or '/') are deliberately preserved.
    out = _GENERIC_TOKEN_RE.sub(_blob, out)
    # Very long unbroken strings that DO look secret-ish (uv/base64url).
    out = re.sub(r"\b[A-Za-z0-9_-]{72,}\b", REDACTED, out)
    return out


def redact_tree(obj):
    """Recursively redact strings inside parsed JSON structures."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, list):
        return [redact_tree(x) for x in obj]
    if isinstance(obj, dict):
        # Never carry obvious raw-secret fields through, even after redaction.
        cleaned = {}
        for k, v in obj.items():
            if k.lower() in {"secret", "match", "token", "key_material", "decoded_secret"}:
                continue
            cleaned[k] = redact_tree(v)
        return cleaned
    return obj


# --------------------------------------------------------------------------- #
# GitHub URL validation (strict, SSRF-safe)
# --------------------------------------------------------------------------- #

_GITHUB_URL_RE = re.compile(
    r"^https://github\.com(?::443)?/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}[A-Za-z0-9])?)"
    r"/(?P<repo>[A-Za-z0-9._-]{1,100}?)(?:\.git)?/?$"
)


def validate_github_url(url: str) -> tuple[str, str, str]:
    """Validate a public GitHub HTTPS URL.

    Returns (canonical_url, owner, repo). Raises ValueError on anything
    that is not a plain https GitHub repository URL.
    """
    if not url or not isinstance(url, str):
        raise ValueError("A repository URL is required.")
    url = url.strip()
    if url.lower().startswith("http://"):
        raise ValueError("Only HTTPS URLs are accepted (http is not allowed).")
    if not url.lower().startswith("https://"):
        raise ValueError("Only https://github.com/<owner>/<repo> URLs are accepted.")
    m = _GITHUB_URL_RE.match(url)
    if not m:
        raise ValueError(
            "Invalid GitHub repository URL. Expected format: https://github.com/<owner>/<repo>"
        )
    owner = m.group("owner")
    repo = m.group("repo").removesuffix(".git")
    if repo.lower() in (".", ".."):
        raise ValueError("Invalid repository name.")
    return f"https://github.com/{owner}/{repo}", owner, repo


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _kill_tree(pid: int) -> None:
    """Forcefully terminate a process and its children (Windows + POSIX)."""
    try:
        import sys as _sys

        if _sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                           capture_output=True, timeout=20)
        else:
            import os as _os
            import signal

            _os.kill(pid, signal.SIGKILL)
    except Exception:  # noqa: BLE001
        pass


# Env for git that refuses any interactive credential prompt: public clones
# need none, and hanging on a credential manager UI is how clones stall.
_NO_PROMPT_GIT_ENV = {
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ASKPASS": "echo",
    "SSH_ASKPASS": "echo",
    "GCM_INTERACTIVE": "never",
    "GIT_HTTP_USER_AGENT": "AccessPilot",
}


def _run(cmd: list[str], cwd: Path | None = None, timeout: int | None = None,
         extra_env: dict | None = None, kill_tree_on_timeout: bool = True) -> subprocess.CompletedProcess:
    env = {k: v for k, v in __import__("os").environ.items() if k.upper() not in
           {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "GIT_TOKEN"}}
    if extra_env:
        env.update(extra_env)
    proc = subprocess.Popen(
        cmd, cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace", env=env,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        if kill_tree_on_timeout:
            _kill_tree(proc.pid)
            try:
                proc.communicate(timeout=20)
            except (OSError, subprocess.TimeoutExpired):
                pass
        raise
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout or "", stderr or "")


def tool_available(name: str) -> bool:
    if find_tool(name) is not None:
        return True
    # pip-audit also runs via `python -m pip_audit` (the scanner's fallback),
    # so an importable module means the scanner is usable even without a CLI.
    if name == "pip-audit":
        import importlib.util

        try:
            return importlib.util.find_spec("pip_audit") is not None
        except (ImportError, ValueError):
            return False
    return False


def find_tool(name: str) -> str | None:
    """Locate a scanner binary: PATH first, then backend/tools/<name>.exe."""
    from config import settings

    p = shutil.which(name)
    if p:
        return p
    for candidate in (settings.tools_dir / f"{name}.exe", settings.tools_dir / name):
        if candidate.is_file():
            return str(candidate)
    return None


def which_path(name: str) -> str | None:
    return find_tool(name)


def _ignored(path: Path) -> bool:
    return bool(set(path.parts) & IGNORED_DIR_PARTS)


def repo_bytes_and_file_count(clone_dir: Path) -> tuple[int, int]:
    total, count = 0, 0
    for p in clone_dir.rglob("*"):
        if p.is_file() and not _ignored(p):
            try:
                total += p.stat().st_size
                count += 1
            except OSError:
                continue
    return total, count


# --------------------------------------------------------------------------- #
# Clone
# --------------------------------------------------------------------------- #


def clone_repo(url: str, scan_dir: Path) -> Path:
    """Shallow clone into scan_dir/repo. Raises RuntimeError on failure."""
    target = scan_dir / "repo"
    scan_dir.mkdir(parents=True, exist_ok=True)
    git = shutil.which("git") or "git"
    # -c credential.helper= : bypass any configured credential helper (GCM);
    #   public repos need no credentials and prompting must never hang.
    # -c core.longpaths=true : Windows MAX_PATH; some repos contain deep paths.
    try:
        result = _run(
            [git, "-c", "credential.helper=", "-c", "core.longpaths=true",
             "clone", "--depth", "1", "--single-branch", "--no-tags",
             url, str(target)],
            timeout=settings.clone_timeout,
            extra_env=_NO_PROMPT_GIT_ENV,
        )
    except subprocess.TimeoutExpired:
        shutil.rmtree(target, ignore_errors=True)
        raise RuntimeError("Cloning timed out. The repository may be too large or unreachable.")
    if result.returncode != 0:
        shutil.rmtree(target, ignore_errors=True)
        err = (result.stderr or result.stdout or "").strip()
        if "not found" in err.lower() or "repository" in err.lower() and "does not exist" in err.lower():
            raise RuntimeError("Repository not found or not accessible as a public GitHub repo.")
        if "credentials" in err.lower() or "authentication" in err.lower():
            raise RuntimeError("Authentication required: this repository does not appear to be public.")
        raise RuntimeError(f"git clone failed: {err[:400]}")

    size, files = repo_bytes_and_file_count(target)
    if size > settings.max_repo_size_mb * 1024 * 1024:
        shutil.rmtree(target, ignore_errors=True)
        raise RuntimeError(
            f"Repository content is {size // (1024 * 1024)} MB, which exceeds the "
            f"{settings.max_repo_size_mb} MB limit."
        )
    return target


# --------------------------------------------------------------------------- #
# Gitleaks (secret detection)
# --------------------------------------------------------------------------- #


def run_gitleaks(clone_dir: Path) -> dict:
    """Returns dict(tool=result, findings=[...]) with redacted evidence."""
    gitleaks = which_path("gitleaks")
    if not gitleaks:
        return {"tool": "gitleaks", "result": "skipped",
                "reason": "gitleaks is not installed (see README for install instructions).",
                "findings": []}
    report = clone_dir.parent / "gitleaks_report.json"
    try:
        proc = _run([gitleaks, "dir", str(clone_dir),
                     "--report-format", "json", "--report-path", str(report),
                     "--no-banner", "--redact", "--exit-code", "0"], timeout=settings.tool_timeout)
    except subprocess.TimeoutExpired:
        return {"tool": "gitleaks", "result": "error", "reason": "gitleaks timed out.", "findings": []}
    if not report.exists():
        return {"tool": "gitleaks", "result": "error",
                "reason": f"gitleaks produced no report: {(proc.stderr or proc.stdout)[:300]}",
                "findings": []}
    try:
        items = json.loads(report.read_text(encoding="utf-8") or "[]")
    except json.JSONDecodeError:
        return {"tool": "gitleaks", "result": "error", "reason": "Could not parse gitleaks output.", "findings": []}
    finally:
        report.unlink(missing_ok=True)

    items = items if isinstance(items, list) else []
    # NOTE: strip repo-relative paths BEFORE any redaction, so redaction can't
    # break the prefix comparison. Secrets are already redacted by gitleaks
    # (--redact) and we never carry the Secret/Match fields through anyway.
    prefix = str(clone_dir).replace("\\", "/") + "/"
    parsed = []
    for f in items:
        if not isinstance(f, dict):
            continue
        raw = str(f.get("File", "")).replace("\\", "/")
        rel = raw[len(prefix):] if raw.startswith(prefix) else raw
        rel = norm_rel(rel, clone_dir)
        if _ignored(Path(rel)):
            continue
        rule = str(f.get("RuleID") or "secret")
        parsed.append({
            "title": f"Potential hardcoded secret ({rule})",
            "severity": "high",
            "category": "Secrets",
            "description": (
                "A secret-like string was detected in repository content. "
                "The value has been redacted."
            ),
            "file_path": rel,
            "line_number": f.get("StartLine"),
            "evidence": redact_text(f"Redacted match (rule: {rule}) at {rel} line {f.get('StartLine')}"),
            "recommendation": (
                "Remove the secret from source, rotate the credential it exposes, "
                "and load it from environment variables or a secret manager instead."
            ),
            "scanner": "gitleaks",
            "rule_id": rule,
        })
    info = {"tool": "gitleaks", "result": "completed", "findings_count": len(parsed)}
    return {"tool": "gitleaks", "result": "completed", "findings": parsed, "info": info}


# --------------------------------------------------------------------------- #
# Semgrep (static analysis)
# --------------------------------------------------------------------------- #

_CATEGORY_HINTS = [
    ("sql", "SQL Injection"),
    ("injection", "Injection"),
    ("subprocess", "Command Injection"),
    ("eval", "Unsafe Code Execution"),
    ("pickle", "Unsafe Deserialization"),
    ("yaml.load", "Unsafe Deserialization"),
    ("deseriali", "Unsafe Deserialization"),
    ("md5", "Weak Cryptography"),
    ("sha1", "Weak Cryptography"),
    ("hash", "Weak Cryptography"),
    ("cipher", "Weak Cryptography"),
    ("random", "Weak Randomness"),
    ("debug", "Debug Misconfiguration"),
    ("certif", "Insecure TLS"),
    ("ssl", "Insecure TLS"),
    ("exec", "Unsafe Code Execution"),
    ("tempfile", "Insecure File Handling"),
]


def categorize(rule: str, message: str) -> str:
    haystack = f"{rule} {message}".lower()
    for needle, cat in _CATEGORY_HINTS:
        if needle in haystack:
            return cat
    return "Static Analysis"


def run_semgrep(clone_dir: Path) -> dict:
    semgrep = which_path("semgrep")
    if not semgrep:
        return {"tool": "semgrep", "result": "skipped",
                "reason": "semgrep is not installed (pip install semgrep).",
                "findings": []}
    # The semgrep.exe wrapper locates pysemgrep.exe via PATH; make sure both
    # our bundled tools dir and the binary's directory are on the child PATH.
    child_path = os.pathsep.join(filter(None, [
        str(settings.tools_dir), str(Path(semgrep).parent),
        os.environ.get("PATH", ""),
    ]))
    try:
        proc = _run([semgrep, "scan", "--config", "p/python", "--json",
                     "--quiet", "--skip-unknown-extensions", str(clone_dir)],
                    timeout=settings.tool_timeout,
                    extra_env={"PATH": child_path})
    except subprocess.TimeoutExpired:
        return {"tool": "semgrep", "result": "error", "reason": "semgrep timed out.", "findings": []}
    except OSError as exc:
        return {"tool": "semgrep", "result": "error",
                "reason": f"semgrep failed to start: {exc}", "findings": []}
    if not (proc.stdout or "").strip():
        return {"tool": "semgrep", "result": "error",
                "reason": f"semgrep produced no output: {(proc.stderr or '')[:300]}",
                "findings": []}
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"tool": "semgrep", "result": "error",
                "reason": "Could not parse semgrep output.", "findings": []}

    sev_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    errors = data.get("errors") or []
    parsed = []
    for r in data.get("results", []):
        rel = str(r.get("path", "")).replace("\\", "/")
        rel = norm_rel(rel, clone_dir)
        if not rel or _ignored(Path(rel)):
            continue
        extra = r.get("extra", {})
        raw_sev = str(extra.get("severity", "INFO")).upper()
        start = (r.get("start") or {}).get("line")
        end = (r.get("end") or {}).get("line")
        app = extra.get("metadata", {})
        title_rule = str(r.get("check_id", "issue"))
        message = str(extra.get("message", "")).strip()
        snippet = redact_text(str(extra.get("lines") or "")[:1200])
        parsed.append({
            "title": f"{title_rule}",
            "severity": sev_map.get(raw_sev, "medium"),
            "category": categorize(title_rule, message),
            "description": message[:1000] or None,
            "file_path": rel,
            "line_number": start,
            "evidence": f"File: {rel}, lines {start}-{end}\n{snippet}".strip(),
            "recommendation": (extra.get("metadata", {}).get("references") and "See rule references for the official fix guidance.")
                              or str(app.get("message", "") or "Review the flagged code and apply secure patterns per the rule documentation."),
            "scanner": "semgrep",
            "rule_id": title_rule,
        })
    info = {"tool": "semgrep", "result": "completed", "findings_count": len(parsed)}
    if errors:
        info["warnings"] = len(errors)
    return {"tool": "semgrep", "result": "completed", "findings": parsed, "info": info}


def strip_prefix(path: str) -> str:
    return path.replace("\\", "/")


def norm_rel(rel: str, clone_dir: Path) -> str:
    rel = rel.replace("\\", "/")
    prefix = strip_prefix(str(clone_dir))
    if rel.startswith(prefix + "/"):
        rel = rel[len(prefix) + 1:]
    return rel


# --------------------------------------------------------------------------- #
# pip-audit (Python dependency scanning)
# --------------------------------------------------------------------------- #


def find_requirements(clone_dir: Path) -> list[Path]:
    found = []
    for p in clone_dir.rglob("requirements*.txt"):
        if _ignored(p):
            continue
        found.append(p)
    return found[:5]


def run_pip_audit(clone_dir: Path, pip_audit_path: str | None) -> dict:
    import sys as _sys

    # pip-audit prefers the binary; fall back to `python -m pip_audit` when the
    # module is installed but its script directory is not on PATH.
    candidates: list[list[str]] = []
    if pip_audit_path:
        candidates.append([pip_audit_path])
    pb = find_tool("pip-audit")
    if pb and [pb] not in candidates:
        candidates.append([pb])
    candidates.append([_sys.executable, "-m", "pip_audit"])

    selected = None
    for cand in candidates:
        try:
            probe = subprocess.run(cand + ["--version"], capture_output=True,
                                   timeout=30, encoding="utf-8", errors="replace")
            if probe.returncode == 0:
                selected = cand
                break
        except (OSError, subprocess.TimeoutExpired):
            continue
    if not selected:
        return {"tool": "pip-audit", "result": "skipped",
                "reason": "pip-audit is not installed (pip install pip-audit).",
                "findings": []}
    req_files = find_requirements(clone_dir)
    if not req_files:
        return {"tool": "pip-audit", "result": "completed", "findings": [],
                "info": {"tool": "pip-audit", "result": "completed", "findings_count": 0,
                         "note": "No requirements*.txt files with pinned, auditable dependencies found."}}
    parsed = []
    seen = set()
    last_err = None
    for req in req_files:
        try:
            proc = _run(selected + ["-r", str(req), "-f", "json", "--progress-spinner", "off"],
                        cwd=clone_dir, timeout=settings.tool_timeout)
        except subprocess.TimeoutExpired:
            return {"tool": "pip-audit", "result": "error", "reason": "pip-audit timed out.", "findings": []}
        out = (proc.stdout or "").strip()
        if not out:
            # pip-audit exits 1 when vulnerabilities exist but still prints JSON.
            # No output at all usually means a resolution/build error.
            err_text = (proc.stderr or proc.stdout or "").strip()
            error_lines = [l for l in err_text.splitlines() if l.strip().startswith(("ERROR:", "error:"))]
            detail = error_lines[-1] if error_lines else err_text[:300]
            last_err = (
                "pip-audit could not resolve the requirements on this machine "
                f"(requires a Python build environment for every pinned package). Underlying error: {detail}"
            )[:400]
            continue
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            last_err = "Could not parse pip-audit JSON output."
            continue
        for dep in data.get("dependencies", []):
            vulns = dep.get("vulns", [])
            if not vulns:
                continue
            rel = norm_rel(str(req), clone_dir)
            for v in vulns:
                vid = v.get("id") or ", ".join(v.get("aliases") or []) or "UNKNOWN"
                key = (dep.get("name"), dep.get("version"), vid, rel)
                if key in seen:
                    continue
                seen.add(key)
                fixes = v.get("fix_versions") or []
                fix_txt = ", ".join(str(fv) for fv in fixes[:4])
                desc = redact_text(str(v.get("description") or "")[:800])
                parsed.append({
                    "title": f"Vulnerable dependency: {dep.get('name')}=={dep.get('version')}",
                    "severity": "medium",
                    "category": "Dependencies",
                    "description": desc or f"Known vulnerability {vid} affects {dep.get('name')} {dep.get('version')}.",
                    "file_path": rel,
                    "line_number": None,
                    "evidence": f"{dep.get('name')}=={dep.get('version')} is affected by {vid}"
                                + (f" (fixed in: {fix_txt})" if fix_txt else ""),
                    "recommendation": f"Upgrade {dep.get('name')} to {fix_txt or 'the latest patched version'}." if fix_txt
                                      else f"Upgrade {dep.get('name')} to the latest safe release.",
                    "scanner": "pip-audit",
                    "rule_id": vid,
                })
    if not parsed and last_err:
        return {"tool": "pip-audit", "result": "error", "reason": last_err, "findings": []}
    info = {"tool": "pip-audit", "result": "completed", "findings_count": len(parsed)}
    return {"tool": "pip-audit", "result": "completed", "findings": parsed, "info": info}


# --------------------------------------------------------------------------- #
# Orchestrated scan
# --------------------------------------------------------------------------- #


def scan_repository(clone_dir: Path) -> tuple[list[dict], list[dict]]:
    """Run every available scanner. Returns (findings, scanner_infos)."""
    findings: list[dict] = []
    infos: list[dict] = []

    results = [run_gitleaks(clone_dir), run_semgrep(clone_dir), run_pip_audit(clone_dir, None)]
    for res in results:
        info = res.get("info") or {"tool": res["tool"], "result": res["result"]}
        if res.get("reason"):
            info["reason"] = res["reason"]
        infos.append(info)
        for f in res.get("findings", []):
            f.setdefault("evidence", "")
            f["evidence"] = redact_text(str(f["evidence"]))[:2000]
            if f.get("description"):
                f["description"] = redact_text(str(f["description"]))
            if f.get("recommendation"):
                f["recommendation"] = redact_text(str(f["recommendation"]))
            findings.append(f)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: order.get(f.get("severity", "medium"), 2))
    return findings, infos
