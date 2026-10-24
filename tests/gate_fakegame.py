"""Stands in for PlateUp in the launch-gate tests: logs what it loads the way KitchenMods does, reads every file the
real game would load (top-level .dll/.assets of each Workshop folder, Mods/<name>/ and its content/), and records
what it read and the arguments it got.

    FAKE_WORKSHOP  the workshop/content/<appid> folder       WG_PLAYER_LOG  where to write the log
    FAKE_MODS      the game's Mods folder (optional)          FAKE_RESULT    JSON report
    FAKE_EXTRA_DIR a folder to "load" that the gate never saw (optional)
    FAKE_PLAY_SECONDS how long to keep running (default 0.5)
"""

import hashlib
import json
import os
import sys
import time
from pathlib import Path

LOADS = (".dll", ".assets")


def main() -> int:
    log = Path(os.environ["WG_PLAYER_LOG"])
    if log.exists():
        log.replace(log.with_name("Player-prev.log"))
    lines = ["Initialize engine version: fake", "Loading mods..."]
    read: dict[str, str] = {}
    errors: dict[str, str] = {}

    def load(folder: Path) -> None:
        for f in sorted(folder.iterdir()) if folder.is_dir() else []:
            if f.is_file() and f.suffix in LOADS:
                try:
                    read[str(f)] = hashlib.sha256(f.read_bytes()).hexdigest()
                except OSError as e:
                    errors[str(f)] = str(e)

    probe = os.environ.get("FAKE_TRY_WRITE")  # what Steam updating a mod mid-launch would run into
    if probe:
        try:
            with open(probe, "r+b"):
                errors["write_probe"] = "writable"
        except OSError as e:
            errors["write_probe"] = type(e).__name__
    if "-nomods" in sys.argv:
        lines.append("Mods disabled by command line")
    else:
        ws = Path(os.environ["FAKE_WORKSHOP"])
        dirs = sorted(p for p in ws.iterdir() if p.is_dir() and p.name.isdigit()) if ws.is_dir() else []
        if os.environ.get("FAKE_EXTRA_DIR"):
            dirs.append(Path(os.environ["FAKE_EXTRA_DIR"]))
        lines.append(f"Found {len(dirs)} workshop mods")
        for d in dirs:
            lines.append(f"... id: {d.name}, dir: {d}")
            load(d)
        mods = os.environ.get("FAKE_MODS")
        n = len(dirs)
        if mods:
            lines.append(f"Searching for mods in {mods}")
            for d in sorted(Path(mods).iterdir()) if Path(mods).is_dir() else []:
                if d.is_dir() and not d.name.startswith("."):
                    load(d)
                    load(d / "content")
                    n += 1
        lines.append(f"Loaded {n} mods...")
    log.parent.mkdir(parents=True, exist_ok=True)
    with open(log, "w", encoding="utf-8") as fh:
        for ln in lines:
            fh.write(ln + "\n")
            fh.flush()
            time.sleep(0.02)
    Path(os.environ["FAKE_RESULT"]).write_text(json.dumps({"argv": sys.argv[1:], "read": read, "errors": errors}))
    time.sleep(float(os.environ.get("FAKE_PLAY_SECONDS", "0.5")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
