# AccessPilot — AI Security Auditor

**Find it. Prove it. Fix it. Verify it.**

AccessPilot is an AI-powered security auditing tool for public GitHub repositories.
It clones a repository into an isolated workspace, runs real security scanners,
lets Google Gemini investigate findings, proposes code patches that must be
explicitly approved, applies approved patches **only** to an isolated working
copy, and verifies fixes in a restricted sandbox. It never modifies your GitHub
repository and never executes repository code on the host.

---

## Features

- 📥 **Real scanning** — Gitleaks (secrets), Semgrep (static analysis), pip-audit (vulnerable Python dependencies). Missing tools are honestly reported as skipped; results are never fabricated.
- 🤖 **Gemini investigation** — explanations of what a finding means, why it's dangerous, how it's exploited, and how to remediate it.
- 🔧 **Gemini patch proposals** — unified diffs generated from the actual source context, shown before anything happens.
- ✅ **Human-approved patching** — patches apply only to an isolated working copy inside the workspace. No commits, no pushes, ever.
- 🧪 **Sandbox verification** — Docker containers (non-root, no network, resource-limited, disposable) run the repo's tests; if Docker is unavailable, a Semgrep re-check of the patched code is used, and if neither is possible the result is honestly `unavailable`.
- 📄 **Full JSON report** at the end of the workflow.
- 🔐 **Secrets are always redacted** before storage, AI calls, UI display, and logs.

## Technology stack

| Layer | Tech |
|---|---|
| Backend | Python 3.11+, FastAPI, SQLAlchemy, SQLite, Pydantic |
| AI | Google Gemini via the official `google-genai` SDK |
| Scanners | Gitleaks, Semgrep, pip-audit |
| Sandbox | Docker (restricted disposable containers) |
| Frontend | React 18, Vite, Tailwind CSS, Lucide icons |
| Git access | Git CLI (shallow clones only) |

## Project structure

```
accesspilot/
├── backend/
│   ├── main.py          # FastAPI app and endpoints
│   ├── config.py        # environment configuration
│   ├── database.py      # SQLite + SQLAlchemy setup
│   ├── models.py        # Scan, Finding, Patch tables
│   ├── schemas.py       # API response schemas
│   ├── scanner.py       # URL validation, cloning, gitleaks/semgrep/pip-audit
│   ├── ai_engine.py     # Gemini investigation / patch / commentary
│   ├── patcher.py       # diff validation + isolated application
│   ├── sandbox.py       # Docker / static verification
│   ├── tools/           # optional bundled scanner binaries (gitleaks.exe etc.)
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/             # React app (pages + components)
│   ├── package.json
│   └── index.html
└── README.md
```

---

## Installation (Windows PowerShell)

```powershell
# 1. Clone or copy the project, then open a terminal in it
cd accesspilot

# 2. Create a Python 3.11+ virtual environment (optional but recommended)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install backend dependencies
cd backend
pip install -r requirements.txt
```

### Backend setup

```powershell
# from the backend/ directory
Copy-Item .env.example .env
notepad .env
```

> **🔑 Where to put your Gemini API key:** in `backend/.env`, in the
> `GEMINI_API_KEY=...` line. Get a free key from
> [Google AI Studio](https://aistudio.google.com/apikey).
> **Never** paste the key into source code and **never** commit the `.env` file
> (it is git-ignored). The key is only read by the backend process and is never
> sent to the frontend.

Then start the backend:

```powershell
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000/docs for the interactive API documentation.

### Frontend setup

```powershell
# in a second terminal
cd frontend
npm install
npm run dev
```

Then open http://localhost:5173.

### Scanner installation

Scanners that are already available are used automatically; anything missing is
reported as **skipped** (never faked).

```powershell
pip install pip-audit      # Python dependency CVE scanning (requires network)

pip install semgrep        # static analysis (macOS/Linux ready; on Windows the
                           # pinned version must be >=1.180 for native support)

# Gitleaks (Windows): download the latest *_windows_x64.zip from
# https://github.com/gitleaks/gitleaks/releases and place gitleaks.exe in
#   backend\tools\
```

`backend\tools\` is a supported location for any scanner binary the backend
should pick up. Alternatively, make the tools available on `PATH`.

### Docker setup (optional, for sandbox verification)

Install [Docker Desktop](https://www.docker.com/products/docker-desktop) and
keep the daemon running. When Docker is available, verification runs inside a
disposable `python:3.11-slim` container with:

- non-root runtime user (`65534`)
- `--network none` during test execution
- CPU (1.0), memory (512 MB) and PID limits (configurable)
- 64 MB write-only tmpfs; code volume mounted read-only
- hard execution deadline; volume/container cleanup afterwards

Without Docker, verification falls back to a Semgrep re-check of the patched
working copy (static analysis only — Semgrep reads files), and if that is not
available either, the outcome is honestly **unavailable**.

---

## Run it yourself (quick start)

Two terminals, both PowerShell, from the project folder:

```powershell
# Terminal 1 — backend (API + scanners)
cd accesspilot\backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000

# Terminal 2 — frontend (the website UI)
cd accesspilot\frontend
$env:Path = "C:\Program Files\nodejs;$env:Path"   # only needed if 'npm' is not found
npm install        # first time only
npm run dev
```

Then open **http://localhost:5173** in your browser.

The API (interactive docs) lives at **http://127.0.0.1:8000/docs**.

### What must be configured once

- **Gemini API key** — in `backend\.env` (created from `.env.example`; see the
  key section above). Scanning works without it; *Investigate* and *Generate
  Patch* return honest 503 guidance until the key is present.
- **Scanners** — `gitleaks.exe` in `backend\tools\`, semgrep and pip-audit
  installed via pip (see *Scanner installation* below). Anything missing is
  reported as skipped on the Settings page — never faked.

### How to use the app

1. **New Scan** tab → paste `https://github.com/<owner>/<repo>` → **Scan**.
   The clone + scan runs in the background (1–4 min for typical repos).
2. **Scan Results** tab → pick the scan (it auto-refreshes while scanning).
   Click any finding → **Investigate with Gemini**, then **Generate Patch**,
   **Approve Patch**, **Verify Patch**. Your GitHub repo is never modified.
3. **Dashboard** shows aggregate numbers; **Settings** shows live backend,
   Gemini, Docker and scanner status.

### Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `npm is not recognized` | Node.js missing from PATH — run `$env:Path = "C:\Program Files\nodejs;$env:Path"` before `npm run dev`, or install Node LTS. |
| Frontend shows "Cannot reach the AccessPilot backend" | Backend terminal isn't running or it is still booting (first `/health` call takes a few seconds while it validates the Gemini key). |
| Port `8000` or `5173` already in use | Stop the old process: `Get-NetTCPConnection -LocalPort 8000 -State Listen \| %{ Stop-Process -Id $_.OwningProcess -Force }` (same for 5173), then restart. |
| A scan stays "scanning" forever | That happens only if the backend process was killed mid-scan. On the next backend start AccessPilot marks such scans failed with an explanation — just start a new scan. |
| `Model '…' is not available to this API key` | Old model name in `GEMINI_MODEL` — set `GEMINI_MODEL=gemini-3.1-flash-lite` (or any listed-when-prompted alternative) in `backend\.env` and restart the backend. Gemini occasionally returns 503 "high demand"; the backend retries with backoff, so just retry after a minute. |
| Clone fails with `cannot create directory` on a deep path | Windows long-path issue — already handled (`core.longpaths=true` is passed to every clone). If you still see it, set Git's global option: `git config --global core.longpaths true`. |
| pip-audit reports errors on some repos | On Windows it may need a build environment to resolve pinned packages; the outcome is reported honestly per-scan, other repos scan fine. |

---



| Method | Path | Description |
|---|---|---|
| GET | `/` | App status + endpoint list |
| GET | `/health` | Backend, database, Gemini, Docker, scanner status |
| POST | `/scan` `{ "repo_url": "https://github.com/owner/repo" }` | Validates URL, shallow-clones, starts background scan, returns scan id |
| GET | `/scan/{scan_id}` | Scan status, summary, findings (with patches) |
| GET | `/scans` | Recent scans |
| POST | `/investigate/{finding_id}` | Gemini analysis of a sanitized finding |
| POST | `/generate-patch/{finding_id}` | Gemini unified diff (nothing applied) |
| POST | `/approve-patch/{patch_id}` | Explicit approval; applies to isolated working copy only |
| POST | `/verify/{patch_id}` | Runs verification; returns `verified` / `failed` / `unavailable` |
| GET | `/report/{scan_id}` | Complete JSON security report |

## Security notes

- Only `https://github.com/<owner>/<repo>` URLs are accepted (SSRF-safe), shallow and size-capped.
- Secret values are redacted everywhere (findings, AI prompts, logs, UI).
- Repository content is treated as untrusted data; prompt-injection inside scanned code is explicitly fenced off in every Gemini call.
- Patch validation rejects path traversal, absolute paths and unknown targets before anything is applied.
- Repository code is never executed on the host; verification is sandboxed or honestly unavailable.

## Known limitations

1. **Gemini required for investigation/patching.** Without a configured key the scan, findings and report still work; `/investigate` and `/generate-patch` return clear 503 guidance instead of inventing data.
2. **Docker verification needs Docker Desktop.** Without it, verification is either the Semgrep re-check (no test suite present) or unavailable.
3. **Security coverage is not complete.** Scanning is limited to the three configured tools for Python-first repositories. A clean scan does not mean the repository is secure.
4. **Secret detection can miss things.** Gitleaks allowlists low-entropy or example-style strings; other secrets may not match its rules.
5. **Patches are proposals.** Generated patches may fail `git apply --check` or verification; results are shown honestly.
6. **Patch verification without Docker relies on repository tests** (pytest) or a Semgrep re-check when no tests exist.
7. **History is not scanned.** Gitleaks runs on the working tree of the last commit (shallow clone), not deep git history.
