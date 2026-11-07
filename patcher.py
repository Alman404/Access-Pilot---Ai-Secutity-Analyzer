"""Patch management.

- Validating a proposed unified diff (paths must stay inside the repo).
- Applying approved patches ONLY to an isolated working copy in the
  workspace. The pristine clone is preserved and GitHub is never touched.
"""

import re
import shutil
import subprocess
from pathlib import Path

from config import settings

def git_binary() -> str:
    return shutil.which("git") or "git"


# --------------------------------------------------------------------------- #
# Diff parsing / validation
# --------------------------------------------------------------------------- #

_HUNK_LINE = re.compile(r"^.{0,40}@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@")
_HEADER = re.compile(r"^(?:--- |\+\+\+ |diff --git a/)")


def parse_diff_files(diff_text: str) -> list[str]:
    """Return the target file paths ('+++ b/...') referenced by the diff."""
    targets = []
    for line in diff_text.splitlines():
        m = re.match(r"^\+\+\+ (?:b/(.+))$", line)
        if m:
            targets.append(m.group(1).strip())
    if not targets:
        # Some diffs use git headers without ---/+++ markers.
        for m in re.finditer(r"^diff --git a/(.+?) b/(.+?)$", diff_text, re.MULTILINE):
            targets.append(m.group(2).strip())
    return targets


def _safe_relpath(path: str) -> Path | None:
    """Reject anything that escapes the workspace or is absolute."""
    p = Path(path.replace("\\", "/"))
    if p.is_absolute() or p.drive:
        return None
    parts = [part for part in p.parts if part not in (".",) and part != ""]
    if any(part == ".." for part in parts):
        return None
    try:
        resolved = (Path("root") / Path(*parts)).resolve()
        root = Path("root").resolve()
        if not str(resolved).startswith(str(root)):
            return None
    except OSError:
        return None
    normalized = Path(*parts)
    return normalized


def _fix_hunk_counts(lines: list[str]) -> list[str]:
    """Recount @@ header line ranges so truncated-context hunks still apply."""
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("@@") and " @@" in line:
            # Collect hunk body
            j = i + 1
            body = []
            while j < len(lines) and not lines[j].startswith("@@") and not lines[j].startswith(("diff --git", "--- ", "+++ ")):
                body.append(lines[j])
                j += 1
            ctx = sum(1 for l in body if l.startswith(" "))
            dele = sum(1 for l in body if l.startswith("-"))
            add_ = sum(1 for l in body if l.startswith("+"))
            m = re.match(r"^@@\s*-(\d+)(?:,(\d+))?\s*\+(\d+)(?:,(\d+))?\s*@@", line)
            if m:
                old_start = int(m.group(1))
                new_start = int(m.group(3))
                head = f"@@ -{old_start},{ctx + dele} +{new_start},{ctx + add_} @@"
                rest = line[m.end():]
                out.append(head + rest)
                out.extend(body)
            else:
                out.append(line)
                out.extend(body)
            i = j
        else:
            out.append(line)
            i += 1
    return out


def normalize_diff(diff_text: str, clone_dir: Path) -> str:
    """Normalize Gemini-style unified diffs into git-apply-friendly ones.

    Handles `--- path` / `+++ path` with or without a/ b/ prefixes and tab
    timestamps. Path-rewriting never introduces anything outside the repo.
    """
    lines = []
    for line in diff_text.splitlines():
        if line.startswith(("--- ", "+++ ")):
            prefix, path = line[:4], line[4:].strip().split("\t")[0]
            if path == "/dev/null":
                lines.append(line)
                continue
            if path.startswith(("a/", "b/")):
                path = path[2:]
            safe = _safe_relpath(path)
            if safe is None:
                raise ValueError(f"Unsafe path in proposed diff: '{path}'.")
            side = "a" if prefix.startswith("---") else "b"
            lines.append(f"{prefix}{side}/{safe.as_posix()}")
        elif line.startswith("diff --git"):
            m = re.match(r"^diff --git a/(.+?) b/(.+?)(?:\s.*)?$", line)
            if m:
                a, b = m.group(1), m.group(2)
                for pfx in ("a/", "b/"):
                    a = a.removeprefix(pfx)
                    b = b.removeprefix(pfx)
                lines.append(f"diff --git a/{a} b/{b}")
            else:
                lines.append(line)
        else:
            lines.append(line)
    normalized = "\n".join(_fix_hunk_counts(lines)) + "\n"
    return normalized


def validate_diff(diff_text: str, clone_dir: Path) -> None:
    """Raise ValueError when the diff is unsafe or unusable."""
    if not diff_text or not diff_text.strip():
        raise ValueError("The proposed diff is empty.")
    if len(diff_text) > 200_000:
        raise ValueError("The proposed diff is unreasonably large.")
    lines = diff_text.splitlines()
    if not any(_HEADER.match(l) for l in lines):
        raise ValueError("The proposed diff has no file headers (not a valid unified diff).")
    if not any(_HUNK_LINE.match(l) for l in lines):
        raise ValueError("The proposed diff has no @@ hunks (not a valid unified diff).")

    targets = parse_diff_files(diff_text)
    if not targets:
        raise ValueError("Could not determine the target files of this diff.")
    if len(targets) != len(set(targets)):
        raise ValueError("The diff contains duplicate file targets.")

    for t in targets:
        t = t.strip().lstrip("b/") if t.startswith("b/") else t
        safe = _safe_relpath(t)
        if safe is None:
            raise ValueError(
                f"Unsafe path in proposed diff: '{t}'. Path traversal and absolute "
                "paths are not allowed."
            )
        full = clone_dir / safe
        if full.is_file():
            continue
        # Creating a brand-new file is only allowed when the diff explicitly
        # treats it as new (--- /dev/null + b/<path>).
        creates_new = (
            re.search(r"^--- /dev/null$", diff_text, re.MULTILINE)
            and re.search(rf"^\+\+\+ b/{re.escape(t)}\s*(?:\(+\d+\))?$", diff_text, re.MULTILINE)
        )
        if not creates_new:
            raise ValueError(
                f"Diff targets '{t}', which does not exist in the repository "
                "and is not marked as a new file (--- /dev/null)."
            )


# --------------------------------------------------------------------------- #
# Working copies
# --------------------------------------------------------------------------- #


def workdir_for(scan_id: str) -> Path:
    return settings.workspace_dir / "scans" / scan_id / "work"


def reset_workdir(scan_id: str, clone_dir: Path) -> Path:
    """Create a FRESH working copy from the pristine clone.

    .git is deliberately not copied: git apply does not require a repo, and
    read-only pack files are the usual source of Windows removal failures.
    """
    import os
    import stat
    import time

    work = workdir_for(scan_id)
    if work.exists():
        def _un(func, path, exc):
            try:
                os.chmod(path, stat.S_IWRITE)
                func(path)
            except OSError:
                pass
        for _ in range(3):
            shutil.rmtree(work, onerror=_un)
            if not work.exists():
                break
            time.sleep(1)
        if work.exists():
            raise ValueError(
                "Could not refresh the isolated working copy on this machine "
                "(a previous working copy is locked by another process)."
            )
    work.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(clone_dir, work,
                    ignore=shutil.ignore_patterns(".git"))
    return work


def apply_patched_diff(scan_id: str, diff_text: str, clone_dir: Path) -> dict:
    """Validate + apply the diff to a fresh working copy. No commits, no push."""
    diff_text = normalize_diff(diff_text, clone_dir)
    validate_diff(diff_text, clone_dir)
    work = reset_workdir(scan_id, clone_dir)

    diff_path = work.parent / "proposed.patch"
    diff_path.write_text(diff_text, encoding="utf-8")

    git = git_binary()
    try:
        check = subprocess.run(
            [git, "apply", "--check", "--verbose", str(diff_path)],
            cwd=str(work), capture_output=True, text=True,
            timeout=120, encoding="utf-8", errors="replace",
        )
        if check.returncode != 0:
            raise ValueError(
                "The diff does not cleanly apply to the current source "
                f"(git apply --check failed). Details: {(check.stderr or check.stdout)[:400]}"
            )
        result = subprocess.run(
            [git, "apply", str(diff_path)],
            cwd=str(work), capture_output=True, text=True,
            timeout=120, encoding="utf-8", errors="replace",
        )
    except subprocess.TimeoutExpired:
        raise ValueError("Applying the patch timed out.")
    if result.returncode != 0:
        raise ValueError(f"Patch could not be applied: {(result.stderr or result.stdout)[:400]}")

    return {"workdir": str(work), "diff_file": str(diff_path)}
