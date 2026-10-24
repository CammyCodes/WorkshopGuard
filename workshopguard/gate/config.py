"""The gate's settings: %LOCALAPPDATA%\\WorkshopGuard\\gate.json (all optional)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, fields
from pathlib import Path


def home() -> Path:
    env = os.environ.get("WG_GATE_HOME")
    if env:
        return Path(env)
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local" / "share")
    return Path(base) / "WorkshopGuard"


@dataclass
class GateConfig:
    # What to do with a mod that looks suspicious but not certainly malicious: ask | block | allow
    suspicious: str = "ask"
    # Blocklists to check every file against: URLs or file paths, {appid} is filled in. A WorkshopGuard server's
    # public blocklist is http://<server>:8081/blocklist/{appid}.json
    blocklists: list[str] = field(default_factory=lambda: ["http://127.0.0.1:8081/blocklist/{appid}.json"])
    blocklist_timeout: float = 1.5
    defender: bool = True
    yara_forge: bool = True
    clamav: str = ""                 # host:port of a clamd, e.g. your WorkshopGuard server's ClamAV
    capa: bool = False               # slow (seconds per DLL); needs capa on PATH and CAPA_RULES
    virustotal_key: str = ""         # online lookups send only the file's SHA-256
    metadefender_key: str = ""
    malwarebazaar_key: str = ""
    watch_while_playing: bool = True  # pre-scan updates Steam downloads mid-session
    verify_game_files: bool = True    # notice the game's own DLLs changing without a Steam update
    splash_after: float = 0.35        # seconds of work before the window appears (no window if it's quicker)

    @classmethod
    def load(cls, h: Path | None = None) -> GateConfig:
        p = (h or home()) / "gate.json"
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return cls()
        except (OSError, ValueError) as e:
            raise RuntimeError(f"{p} isn't valid JSON: {e}") from e
        names = {f.name for f in fields(cls)}
        cfg = cls(**{k: v for k, v in raw.items() if k in names})
        if cfg.suspicious not in ("ask", "block", "allow"):
            cfg.suspicious = "ask"
        return cfg
