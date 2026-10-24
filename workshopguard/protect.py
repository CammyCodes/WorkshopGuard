"""Protect mode: guard the Workshop mods already on a player's PC.

Steam keeps subscribed items in steamapps/workshop/content/<appid>/<item>. Mount that folder at /protect and this
scans every item there, then rescans any that change (Steam installing an update). A malicious item is moved out
to the quarantine so the game can't load it, and you get an alert. Unsubscribe from it too, or Steam will put it
back on its next update check (and it'll be caught again).
"""

from __future__ import annotations

import logging
import os
import shutil
import threading
import time
from pathlib import Path

from . import steam

log = logging.getLogger(__name__)


def fingerprint(folder: Path) -> str:
    n = size = newest = 0
    for dirpath, _, files in os.walk(folder):
        for f in files:
            try:
                st = os.stat(os.path.join(dirpath, f))
            except OSError:
                continue
            n += 1
            size += st.st_size
            newest = max(newest, int(st.st_mtime))
    return f"{n}:{size}:{newest}"


class Protector:
    def __init__(self, guard):
        self.g = guard
        self.cfg = guard.cfg

    def roots(self):
        for p in self.cfg.games:
            root = self.cfg.protect_dir / str(p.appid)
            if root.is_dir():
                yield p, root

    def enabled(self) -> bool:
        return any(True for _ in self.roots())

    def sweep(self) -> int:
        scanned = 0
        for p, root in self.roots():
            folders = [d for d in sorted(root.iterdir()) if d.is_dir() and d.name.isdigit()]
            changed = []
            for d in folders:
                fp = fingerprint(d)
                row = self.g.db.q("SELECT fingerprint FROM local_items WHERE path=?", str(d))
                if not row or row[0]["fingerprint"] != fp:
                    changed.append((d, fp))
            if not changed:
                continue
            log.info("[%s] protect: %d new/changed item(s) on this PC", p.name, len(changed))
            info = {it.id: it for it in _details([d.name for d, _ in changed], p.appid)}
            for d, fp in changed:
                it = info.get(d.name) or steam.Item(p.appid, d.name, title=d.name)
                try:
                    r = self.g.scan_and_record(p, it, d)
                except Exception:  # noqa: BLE001
                    log.exception("protect: scanning %s failed", d)
                    continue
                scanned += 1
                self.g.db.x("INSERT OR REPLACE INTO local_items(path,fingerprint,verdict,scanned_at) VALUES(?,?,?,?)",
                            str(d), fp, r.verdict, int(time.time()))
                if r.verdict == "malicious" and self.cfg.protect_action == "quarantine":
                    self._quarantine(p, it, d)
        return scanned

    def _quarantine(self, p, it, folder: Path):
        dest = self.cfg.quarantine_dir / "from-this-pc" / str(p.appid) / f"{it.id}-{int(time.time())}"
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.move(str(folder), str(dest))
        except OSError as e:
            log.error("protect: could NOT move %s out of the Steam folder (%s). Mount it read-write.", folder, e)
            self.g.db.x("UPDATE items SET error=? WHERE appid=? AND id=?",
                        f"Protect mode could not move it out of your Steam folder: {e}", p.appid, it.id)
            return
        (dest / "WORKSHOPGUARD_README.txt").write_text(
            "WorkshopGuard moved this Workshop item out of your Steam folder because it looks malicious.\n"
            "Do not open or run anything in here. Unsubscribe from the item on Steam.\n")
        self.g.db.x("UPDATE items SET error=? WHERE appid=? AND id=?",
                    "Moved out of your Steam folder by protect mode. Unsubscribe from it on Steam.", p.appid, it.id)
        self.g.db.x("DELETE FROM local_items WHERE path=?", str(folder))
        log.warning("[%s] protect: MOVED %s (%s) to quarantine", p.name, it.id, it.title)

    def run_forever(self):
        log.info("Protect mode: watching %s every %ss (action: %s)",
                 ", ".join(str(r) for _, r in self.roots()), self.cfg.protect_seconds, self.cfg.protect_action)
        while True:
            try:
                self.sweep()
            except Exception:  # noqa: BLE001
                log.exception("protect sweep failed")
            time.sleep(self.cfg.protect_seconds)

    def start_thread(self) -> threading.Thread:
        t = threading.Thread(target=self.run_forever, daemon=True, name="protect")
        t.start()
        return t


def _details(ids: list[str], appid: int):
    try:
        return steam.details(ids, appid)
    except Exception:  # noqa: BLE001 - offline is fine, titles are just nicer
        return []
