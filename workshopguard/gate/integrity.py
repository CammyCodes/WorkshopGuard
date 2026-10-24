"""The game's own code files: notice them changing when Steam didn't update the game.

A baseline of every .exe/.dll in the install (minus the local Mods folder) is taken per Steam build. Each launch
compares sizes and modified times (~20 ms for PlateUp's 270 files) and re-hashes anything that differs; a full
re-hash runs in the background while the game plays, which also catches a file whose timestamps were faked.
Loader/hijack DLLs (winhttp.dll and friends, how BepInEx-style injectors and some malware get in before the game)
are reported whenever they appear next to the game.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..scan.model import Finding

CODE_EXTS = (".exe", ".dll")
# DLL names Windows looks for next to an exe first: drop one beside the game and it runs inside it before anything.
HIJACK_NAMES = {"winhttp.dll", "version.dll", "winmm.dll", "dinput8.dll", "dxgi.dll", "d3d9.dll", "d3d11.dll",
                "dsound.dll", "xinput1_3.dll", "xinput1_4.dll", "wininet.dll", "iphlpapi.dll", "dbghelp.dll",
                "doorstop_config.ini", ".doorstop_version"}
LOADER_DIRS = {"bepinex", "melonloader", "doorstop_libs", "unityexplorer"}


@dataclass
class GameCheck:
    status: str = "ok"                # ok | baseline | changed | updating | off
    changed: list[str] = field(default_factory=list)
    added: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    loaders: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    files: dict[str, tuple[str, int]] = field(default_factory=dict)   # the flagged files, hashed

    @property
    def flagged(self) -> bool:
        return bool(self.findings)


def _code_files(game, skip: Path | None) -> dict[str, list]:
    out: dict[str, list] = {}
    root = game.install_dir
    skip_n = os.path.normcase(str(skip)) if skip else None
    for dirpath, dirs, files in os.walk(root):
        if skip_n and os.path.normcase(dirpath).startswith(skip_n):
            dirs[:] = []
            continue
        for f in files:
            if f.lower().endswith(CODE_EXTS) or f.lower() in HIJACK_NAMES:
                full = os.path.join(dirpath, f)
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                out[Path(full).relative_to(root).as_posix()] = [st.st_size, st.st_mtime_ns]
    return out


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def _loaders(game) -> list[str]:
    found = []
    for d in {game.install_dir, game.exe.parent}:
        try:
            for e in os.scandir(d):
                n = e.name.lower()
                if (e.is_file() and n in HIJACK_NAMES) or (e.is_dir() and n in LOADER_DIRS):
                    found.append(Path(e.path).relative_to(game.install_dir).as_posix())
        except OSError:
            pass
    return sorted(set(found))


def check(game, state, mods_dir: Path | None) -> GameCheck:
    gc = GameCheck()
    if game.updating:
        gc.status = "updating"
        return gc
    now = _code_files(game, mods_dir)
    row = state.q("SELECT * FROM game WHERE appid=?", game.appid)
    row = row[0] if row else None
    approved = set(state.get(f"game_approved:{game.appid}", []))
    gc.loaders = [p for p in _loaders(game) if p not in approved]
    for p in gc.loaders:
        f = game.install_dir / p
        sha = _sha(f) if f.is_file() else ""
        if sha and sha in approved:
            continue
        if f.is_file():
            gc.files[p] = (sha, f.stat().st_size)
        gc.findings.append(Finding("integrity", "high", "integrity.loader",
                                   f"A mod loader / DLL-hijack file next to the game ({Path(p).name}): it runs "
                                   f"inside {game.exe.name} before anything else", p))
    if row is None or row["buildid"] != game.buildid:
        gc.status = "baseline"   # new build from Steam (or first run): re-baselined in the background
        return gc
    base: dict[str, list] = json.loads(row["files"] or "{}")
    for rel, (size, mtime) in now.items():
        b = base.get(rel)
        if b is None:
            gc.added.append(rel)
        elif b[0] != size or b[1] != mtime:
            gc.changed.append(rel)
    gc.missing = [rel for rel in base if rel not in now]
    touched = []
    for rel in gc.changed + gc.added:
        p = game.install_dir / rel
        try:
            sha = _sha(p)
        except OSError:
            continue
        b = base.get(rel)
        if b is not None and len(b) > 2 and b[2] == sha:
            touched.append((rel, now[rel] + [sha]))  # same bytes, new timestamp: just remember it
            continue
        if sha in approved:
            continue
        gc.files[rel] = (sha, now[rel][0])
        what = "is new" if b is None else "changed"
        gc.findings.append(Finding("integrity", "high", "integrity.modified",
                                   f"Game file {what} since Steam installed build {game.buildid}, but Steam didn't "
                                   f"update the game", rel))
    for rel in json.loads(row["tampered"] or "[]"):
        if rel not in gc.files and (game.install_dir / rel).is_file():
            p = game.install_dir / rel
            sha = _sha(p)
            if sha in approved:
                continue
            gc.files[rel] = (sha, p.stat().st_size)
            gc.findings.append(Finding("integrity", "high", "integrity.forged",
                                       "Game file's contents changed but its date didn't (found by the last "
                                       "background check)", rel))
    if touched:
        for rel, v in touched:
            base[rel] = v
        state.x("UPDATE game SET files=? WHERE appid=?", json.dumps(base), game.appid)
    gc.status = "changed" if gc.findings else "ok"
    return gc


def approve(game, state, gc: GameCheck) -> None:
    """The player said these game files are fine: accept their current contents."""
    approved = set(state.get(f"game_approved:{game.appid}", []))
    approved |= {sha for sha, _ in gc.files.values()} | set(gc.loaders)
    state.set(f"game_approved:{game.appid}", sorted(approved))
    row = state.q("SELECT files, tampered FROM game WHERE appid=? AND buildid=?", game.appid, game.buildid)
    if row:
        base = json.loads(row[0]["files"] or "{}")
        for rel, (sha, _) in gc.files.items():
            try:
                st = (game.install_dir / rel).stat()
            except OSError:
                continue
            base[rel] = [st.st_size, st.st_mtime_ns, sha]
        tampered = [r for r in json.loads(row[0]["tampered"] or "[]") if r not in gc.files]
        state.x("UPDATE game SET files=?, tampered=? WHERE appid=?", json.dumps(base), json.dumps(tampered),
                game.appid)


def full_verify(game, state, mods_dir: Path | None, stop=None) -> list[str]:
    """Hash every code file (slowly, in the background). Takes a fresh baseline for a new build; otherwise
    returns the files whose contents no longer match, and remembers them for the next launch."""
    now = _code_files(game, mods_dir)
    row = state.q("SELECT * FROM game WHERE appid=?", game.appid)
    row = row[0] if row else None
    fresh = row is None or row["buildid"] != game.buildid
    base: dict[str, list] = {} if fresh else json.loads(row["files"] or "{}")
    bad = []
    for rel, st in now.items():
        if stop is not None and stop.is_set():
            return []
        try:
            sha = _sha(game.install_dir / rel)
        except OSError:
            continue
        b = base.get(rel)
        if b is not None and len(b) > 2 and b[2] != sha and b[0] == st[0] and b[1] == st[1]:
            bad.append(rel)
            continue
        # new files only join the baseline through a new Steam build or the player's approval
        if fresh or (b is not None and (len(b) < 3 or ((b[0], b[1]) != (st[0], st[1]) and b[2] == sha))):
            base[rel] = st + [sha]
        time.sleep(0.002)  # stay out of the game's way
    state.x("""INSERT INTO game(appid, buildid, files, verified_at, tampered) VALUES(?,?,?,?,?)
               ON CONFLICT(appid) DO UPDATE SET buildid=excluded.buildid, files=excluded.files,
                 verified_at=excluded.verified_at, tampered=excluded.tampered""",
            game.appid, game.buildid, json.dumps(base), int(time.time()), json.dumps(bad))
    return bad
