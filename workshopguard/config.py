"""Settings, all from environment variables (see .env.example)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from . import games


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _int(name: str, default: int) -> int:
    v = _env(name)
    return int(v) if v else default


def _bool(name: str, default: bool) -> bool:
    v = _env(name).lower()
    return default if not v else v in ("1", "true", "yes", "on")


@dataclass
class Config:
    games: list[games.GameProfile] = field(default_factory=list)
    data_dir: Path = Path("/data")
    poll_minutes: int = 15
    # none | all | <number of most recent items>, applied once per game on first run
    backfill: str = "none"
    max_item_mb: int = 2048
    pages_per_poll: int = 3
    keep_clean_files: bool = False
    quarantine_flagged: bool = True

    steam_username: str = ""
    steam_web_api_key: str = ""

    clamav_host: str = ""
    clamav_port: int = 3310
    virustotal_api_key: str = ""
    metadefender_api_key: str = ""
    malwarebazaar_api_key: str = ""
    # local engines to run; online ones switch on when their key is set
    engines: set[str] = field(default_factory=lambda: {"clamav", "yara", "yara-forge", "capa"})
    upload_unknown: bool = False
    protect_dir: Path = Path("/protect")
    protect_action: str = "quarantine"   # quarantine | alert
    protect_seconds: int = 60

    discord_webhook_url: str = ""
    webhook_url: str = ""
    notify_on: set[str] = field(default_factory=lambda: {"malicious", "suspicious"})
    public_url: str = ""

    dashboard_port: int = 8080
    dashboard_host: str = "0.0.0.0"
    extra_rules_dir: Path = Path("/rules")

    @property
    def db_path(self) -> Path:
        return self.data_dir / "workshopguard.db"

    @property
    def work_dir(self) -> Path:
        return self.data_dir / "work"

    @property
    def quarantine_dir(self) -> Path:
        return self.data_dir / "quarantine"

    @property
    def steam_dir(self) -> Path:
        return self.data_dir / "steam"


def load() -> Config:
    tokens = [t for t in _env("GAMES", "plateup").replace(";", ",").split(",") if t.strip()]
    c = Config(
        games=[games.resolve(t) for t in tokens],
        data_dir=Path(_env("DATA_DIR", "/data")),
        poll_minutes=_int("POLL_MINUTES", 15),
        backfill=_env("BACKFILL", "none").lower() or "none",
        max_item_mb=_int("MAX_ITEM_MB", 2048),
        pages_per_poll=_int("PAGES_PER_POLL", 3),
        keep_clean_files=_bool("KEEP_CLEAN_FILES", False),
        quarantine_flagged=_bool("QUARANTINE_FLAGGED", True),
        steam_username=_env("STEAM_USERNAME"),
        steam_web_api_key=_env("STEAM_WEB_API_KEY"),
        clamav_host=_env("CLAMAV_HOST"),
        clamav_port=_int("CLAMAV_PORT", 3310),
        virustotal_api_key=_env("VIRUSTOTAL_API_KEY"),
        metadefender_api_key=_env("METADEFENDER_API_KEY"),
        malwarebazaar_api_key=_env("MALWAREBAZAAR_API_KEY"),
        engines={e.strip().lower() for e in _env("ENGINES", "clamav,yara,yara-forge,capa").split(",") if e.strip()},
        upload_unknown=_bool("UPLOAD_UNKNOWN", False),
        protect_dir=Path(_env("PROTECT_DIR", "/protect")),
        protect_action=_env("PROTECT_ACTION", "quarantine").lower(),
        protect_seconds=_int("PROTECT_SECONDS", 60),
        discord_webhook_url=_env("DISCORD_WEBHOOK_URL"),
        webhook_url=_env("WEBHOOK_URL"),
        notify_on={s.strip().lower() for s in _env("NOTIFY_ON", "malicious,suspicious").split(",") if s.strip()},
        public_url=_env("PUBLIC_URL").rstrip("/"),
        dashboard_port=_int("DASHBOARD_PORT", 8080),
        dashboard_host=_env("DASHBOARD_HOST", "0.0.0.0"),
        extra_rules_dir=Path(_env("EXTRA_RULES_DIR", "/rules")),
    )
    if c.protect_action not in ("quarantine", "alert"):
        raise ValueError("PROTECT_ACTION must be quarantine or alert")
    if c.backfill not in ("none", "all") and not c.backfill.isdigit():
        raise ValueError("BACKFILL must be none, all or a number")
    for d in (c.data_dir, c.work_dir, c.quarantine_dir, c.steam_dir):
        d.mkdir(parents=True, exist_ok=True)
    return c
