"""Every installed mod and the SHA-256 of every file in it.

Everything is hashed in full on every launch: it's the only check a tampered timestamp can't fool, and it's cheap
(~40 ms for a typical PlateUp Workshop, a few hundred MB/s on a cold disk). Files the game will load are opened
with a share mode that refuses writers and deleters, and stay that way until the game has read them.
"""

from __future__ import annotations

import hashlib
import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from ..scan.model import Finding
from .winlock import open_locked

CHUNK = 1 << 20
POOL = ThreadPoolExecutor(max_workers=min(8, (os.cpu_count() or 4)), thread_name_prefix="hash")


@dataclass
class Item:
    key: str
    appid: int
    kind: str                 # workshop | local | game
    path: Path
    id: str
    title: str
    files: dict[str, tuple[str, int]] = field(default_factory=dict)   # rel -> (sha256, size)
    notes: list[Finding] = field(default_factory=list)                # links, unreadable or busy files
    digest: str = ""
    busy: list[str] = field(default_factory=list)                     # files another program is still writing
    handles: list = field(default_factory=list)

    def release(self) -> None:
        for h in self.handles:
            try:
                h.close()
            except OSError:
                pass
        self.handles.clear()

    @property
    def locked(self) -> int:
        return len(self.handles)


def collect(game, adapter) -> list[Item]:
    items: list[Item] = []
    for root in game.workshop_dirs:
        try:
            subs = sorted(root.iterdir())
        except OSError:
            continue
        for d in subs:
            if d.is_dir() and d.name.isdigit():
                items.append(Item(f"ws:{game.appid}:{d.name}", game.appid, "workshop", d, d.name, d.name))
    for d in adapter.local_mod_dirs(game):
        items.append(Item(f"local:{game.appid}:{d.name.lower()}", game.appid, "local", d, d.name, d.name))
    return items


def _walk(root: Path, notes: list[Finding]):
    """(rel, path) for every file, not following links or junctions (they're reported instead)."""
    stack = [(root, "")]
    while stack:
        d, prefix = stack.pop()
        try:
            entries = list(os.scandir(d))
        except OSError as e:
            notes.append(Finding("files", "medium", "files.unreadable_dir", f"Folder can't be read ({e.strerror})",
                                 prefix or "."))
            continue
        for e in entries:
            rel = f"{prefix}{e.name}"
            try:
                if e.is_symlink() or getattr(e, "is_junction", lambda: False)():
                    notes.append(Finding("files", "medium", "files.symlink",
                                         f"Link to somewhere outside the mod ({os.readlink(e.path)!s:.120})", rel))
                elif e.is_dir(follow_symlinks=False):
                    stack.append((Path(e.path), rel + "/"))
                elif e.is_file(follow_symlinks=False):
                    yield rel, e.path
            except OSError as err:
                notes.append(Finding("files", "low", "files.unreadable", f"Could not read ({err.strerror})", rel))


def _hash(path: str, lock: bool):
    """(sha256, size, handle-or-None). Raises PermissionError if a lock was asked for and someone is writing."""
    fh = open_locked(path) if lock else open(path, "rb")
    try:
        h = hashlib.sha256()
        size = 0
        while chunk := fh.read(CHUNK):
            h.update(chunk)
            size += len(chunk)
    except BaseException:
        fh.close()
        raise
    if lock:
        return h.hexdigest(), size, fh
    fh.close()
    return h.hexdigest(), size, None


def digest_of(files: dict[str, tuple[str, int]]) -> str:
    h = hashlib.sha256()
    for rel in sorted(files):
        h.update(f"{rel}\0{files[rel][0]}\n".encode("utf-8", "surrogateescape"))
    return h.hexdigest()


def hash_items(items: list[Item], adapter, lock: bool = True, retries: int = 3) -> None:
    """Hash every file of every item in parallel. Loadable files stay locked (item.handles) when `lock` is set."""
    jobs = []
    for it in items:
        it.files, it.notes, it.busy = {}, [], []
        it.release()
        for rel, path in _walk(it.path, it.notes):
            jobs.append((it, rel, path, lock and adapter.loadable(it.kind, rel)))

    def one(job):
        it, rel, path, want_lock = job
        for attempt in range(retries):
            try:
                return job, _hash(path, want_lock), None
            except PermissionError as e:  # sharing violation: Steam (or something) is writing it right now
                if attempt + 1 < retries:
                    time.sleep(0.4 * (attempt + 1))
                    continue
                return job, None, e
            except OSError as e:
                return job, None, e
        return job, None, None

    for (it, rel, path, want_lock), res, err in POOL.map(one, jobs):
        if res is not None:
            sha, size, fh = res
            it.files[rel] = (sha, size)
            if fh is not None:
                it.handles.append(fh)
        elif isinstance(err, PermissionError):
            it.busy.append(rel)
            it.notes.append(Finding("files", "high", "files.busy",
                                    "Another program kept writing this file while it was being checked", rel))
        elif isinstance(err, FileNotFoundError):
            continue  # removed while we looked (Defender quarantine, Steam update): it won't load either
        else:
            it.notes.append(Finding("files", "low", "files.unreadable", f"Could not read ({err})", rel))
    for it in items:
        it.digest = digest_of(it.files)


def fingerprint(folder: Path) -> str:
    """Cheap change detector for the in-game watcher: names, sizes and modified times only."""
    h = hashlib.sha256()
    for dirpath, dirs, files in os.walk(folder):
        dirs.sort()
        for f in sorted(files):
            try:
                st = os.stat(os.path.join(dirpath, f))
            except OSError:
                continue
            h.update(f"{dirpath}\0{f}\0{st.st_size}\0{st.st_mtime_ns}\n".encode("utf-8", "surrogateescape"))
    return h.hexdigest()
