"""What the gate needs to know about how a particular game loads mods.

PlateUp (read from its KitchenMods.dll): ModPreload.LoadMods() runs at boot. SteamWorkshopModSource takes every
subscribed item's folder and loads the top-level *.dll (Assembly.Load of the bytes, plus a matching .pdb) and
*.assets files; FolderModSource does the same for each <game>/Mods/<name>/ and its content/ subfolder. Its log
says which folders it used ("... id: <id>, dir: <path>", "Searching for mods in <path>") and then "Loaded N
mods...". `-nomods` on the command line turns mods off.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path


def norm(p: str | Path) -> str:
    return os.path.normcase(os.path.abspath(str(p).rstrip("\\/")))


@dataclass
class LoadReport:
    confirmed: bool = False           # the game said it finished loading mods
    mods_disabled: bool = False
    loaded_dirs: list[str] = field(default_factory=list)
    unvetted: list[str] = field(default_factory=list)   # folders the game used that the gate didn't check
    seconds: float = 0.0


class Adapter:
    """Any game: its Workshop folders, everything in them treated as loadable."""
    nomods_arg: str | None = None
    exe_rel: str | None = None       # the game's exe inside its install folder, if not the obvious one
    name = ""
    theme = "default"                # the gate windows' look (ui.THEMES)

    def local_mod_dirs(self, game) -> list[Path]:
        return []

    def loadable(self, kind: str, rel: str) -> bool:
        return True

    def mods_root(self, game) -> Path | None:
        return None

    def watch_load(self, proc, started: float, vetted: set[str], timeout: float = 120.0) -> LoadReport | None:
        return None


class PlateUp(Adapter):
    nomods_arg = "-nomods"
    exe_rel = "PlateUp/PlateUp.exe"
    name = "PlateUp!"
    theme = "plateup"
    LOAD_EXTS = (".dll", ".pdb", ".assets")
    _ITEM = re.compile(r"^\.\.\. id: (\d+), dir: (.+?)\s*$")
    _FOLDER = re.compile(r"^Searching for mods in (.+?)\s*$")
    _DONE = re.compile(r"^Loaded \d+ mods\.\.\.")

    def mods_root(self, game) -> Path | None:
        return game.exe.parent / "Mods"

    def local_mod_dirs(self, game) -> list[Path]:
        mods = self.mods_root(game)
        if not mods.is_dir():
            return []
        return [d for d in sorted(mods.iterdir()) if d.is_dir() and not d.name.startswith(".")]

    def loadable(self, kind: str, rel: str) -> bool:
        parts = rel.split("/")
        if kind == "local" and len(parts) == 2 and parts[0].lower() == "content":
            parts = parts[1:]
        return len(parts) == 1 and parts[0].lower().endswith(self.LOAD_EXTS)

    def log_path(self) -> Path:
        env = os.environ.get("WG_PLAYER_LOG")
        if env:
            return Path(env)
        return Path.home() / "AppData" / "LocalLow" / "It's Happening" / "PlateUp" / "Player.log"

    def watch_load(self, proc, started: float, vetted: set[str], timeout: float = 120.0) -> LoadReport | None:
        """Follow the game's fresh Player.log until it has finished loading mods. Returns None if it never says."""
        log = self.log_path()
        rep = LoadReport()
        end = time.monotonic() + timeout
        pos = 0
        buf = ""
        while time.monotonic() < end and proc.poll() is None:
            try:
                st = log.stat()
                if st.st_mtime + 2 < started:  # still last session's log; Unity rotates it on start
                    raise FileNotFoundError
                if st.st_size < pos:
                    pos, buf = 0, ""
                with open(log, "r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(pos)
                    chunk = fh.read()
                    pos = fh.tell()
            except OSError:
                time.sleep(0.2)
                continue
            buf += chunk
            lines = buf.split("\n")
            buf = lines.pop()
            for ln in lines:
                ln = ln.rstrip("\r")
                if ln.startswith("Mods disabled by command line"):
                    rep.mods_disabled = rep.confirmed = True
                m = self._ITEM.match(ln) or self._FOLDER.match(ln)
                if m:
                    d = m.group(m.lastindex)
                    rep.loaded_dirs.append(d)
                    if os.path.isdir(d) and norm(d) not in vetted and _has_files(d):
                        rep.unvetted.append(d)
                if self._DONE.match(ln):
                    rep.confirmed = True
            if rep.confirmed:
                break
            time.sleep(0.1)
        rep.seconds = time.time() - started
        return rep if rep.confirmed else None


def _has_files(d: str) -> bool:
    try:
        return any(e.is_file() or e.is_dir() for e in os.scandir(d))
    except OSError:
        return False


def for_appid(appid: int) -> Adapter:
    return {1599600: PlateUp()}.get(appid, Adapter())
