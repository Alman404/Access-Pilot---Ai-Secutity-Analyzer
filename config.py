"""AccessPilot configuration.

All configuration comes from environment variables (optionally loaded from a
.env file next to this module). API keys are NEVER logged or returned to the
frontend.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parent

load_dotenv(BACKEND_DIR / ".env")


def _env_bool(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


class Settings:
    app_name: str = "AccessPilot"
    version: str = "0.1.0"

    # --- Gemini ---
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "").strip()
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-3.8-flash").strip() or "gemini-3.8-flash"

    # --- Database ---
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./accesspilot.db")

    # --- Workspace / limits ---
    workspace_dir: Path = Path(
        os.getenv("WORKSPACE_DIR", str(BACKEND_DIR / "workspace"))
    ).resolve()
    clone_timeout: int = int(os.getenv("CLONE_TIMEOUT", "180"))          # seconds
    tool_timeout: int = int(os.getenv("TOOL_TIMEOUT", "900"))           # per scanner / verification
    tools_dir: Path = Path(os.getenv("TOOLS_DIR", str(BACKEND_DIR / "tools"))).resolve()
    max_repo_size_mb: int = int(os.getenv("MAX_REPO_SIZE_MB", "120"))   # clone size guard
    sandbox_memory: str = os.getenv("SANDBOX_MEMORY", "512m")
    sandbox_cpus: str = os.getenv("SANDBOX_CPUS", "1.0")

    # --- CORS ---
    cors_origins: list[str] = [
        o.strip()
        for o in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173",
        ).split(",")
        if o.strip()
    ]

    @property
    def gemini_configured(self) -> bool:
        return bool(self.gemini_api_key)


settings = Settings()
settings.workspace_dir.mkdir(parents=True, exist_ok=True)
