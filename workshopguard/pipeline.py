"""The watch loop: discover new/updated items -> download -> scan -> record -> alert -> clean up."""

from __future__ import annotations

import atexit
import json
import logging
import os
import shutil
import time
from pathlib import Path

from . import games, steam, testdata
from .config import Config
from .db import DB
from .downloader import Downloader, LoginRequired
from .notify import Notifier
from .scan.clamav import ClamAV
from .scan import capa_engine
from .scan.engine import Scanners, scan_dir
from .scan.model import Finding, ScanResult, verdict_for
from .scan.online import MalwareBazaar, MetaDefender, VirusTotal
from .scan.yarascan import Yara

log = logging.getLogger(__name__)
BATCH_BYTES = 1024 * 1024 * 1024
BATCH_ITEMS = 8


class Guard:
    def __init__(self, cfg: Config, *, deep: bool = False, upload: bool | None = None, watcher: bool = False):
        """deep=True runs every engine available, whatever ENGINES says (the deep-scan command).
        watcher=True is the long-running service; one-off commands get their own SteamCMD folder so they can run
        while it's busy."""
        self.cfg = cfg
        self.db = DB(cfg.db_path)
        install = cfg.work_dir / ("steamcmd" if watcher else f"steamcmd-cli-{os.getpid()}")
        self.dl = Downloader(install, cfg.steam_username)
        self.dl.anon_ok = {int(k): v for k, v in (self.db.get("anon_ok", {}) or {}).items()}
        if watcher:
            # recover from a restart mid-scan: requeue interrupted items, drop half-finished downloads
            self.db.x("UPDATE items SET status='queued' WHERE status='scanning'")
            self.dl.reset()
            if cfg.steam_username != self.db.get("steam_username", ""):
                # a Steam account was added or changed: retry downloads that failed for lack of one straight away
                self.db.x("UPDATE items SET status='queued' WHERE status='error'")
                self.db.set("steam_username", cfg.steam_username)
        else:
            atexit.register(shutil.rmtree, install, True)
        want = cfg.engines | ({"clamav", "yara", "yara-forge", "capa"} if deep else set())
        upload = cfg.upload_unknown if upload is None else upload
        clam = None
        if "clamav" in want and cfg.clamav_host:
            clam = ClamAV(cfg.clamav_host, cfg.clamav_port)
            log.info("Waiting for ClamAV at %s:%s ...", cfg.clamav_host, cfg.clamav_port)
            if clam.wait_ready(900):
                log.info("ClamAV ready: %s", clam.version())
            else:
                log.error("ClamAV never came up; scanning without it")
                clam = None
        online = []
        if cfg.virustotal_api_key:
            online.append(VirusTotal(cfg.virustotal_api_key, upload))
        if cfg.metadefender_api_key:
            online.append(MetaDefender(cfg.metadefender_api_key, upload))
        if cfg.malwarebazaar_api_key:
            online.append(MalwareBazaar(cfg.malwarebazaar_api_key))
        self.scanners = Scanners(
            yara=Yara(cfg.extra_rules_dir, forge="yara-forge" in want) if "yara" in want else None,
            clamav=clam,
            capa="capa" in want and capa_engine.available(),
            online=online,
            cache=self.db,
        )
        log.info("Engines: %s", ", ".join(self.scanners.enabled()))
        self.notifier = Notifier(cfg.discord_webhook_url, cfg.webhook_url, cfg.notify_on, cfg.public_url)

    # --- discovery --------------------------------------------------------------------------------------------
    def discover(self, p: games.GameProfile) -> int:
        """Queue new uploads and updates. Returns how many items were queued."""
        key = f"since:{p.appid}"
        first = self.db.get(key) is None
        since = self.db.get(key) or int(time.time())
        queued = 0

        if first:
            bf = self.cfg.backfill
            log.info("[%s] first run, BACKFILL=%s", p.name, bf)
            limit = None if bf == "all" else (int(bf) if bf.isdigit() else 0)
            pages = None if limit is None else max(1, (limit + 29) // 30)
            if limit != 0:
                for n, it in enumerate(steam.iter_items(p.appid, "lastupdated", pages, self.cfg.steam_web_api_key)):
                    if limit is None or n < limit:
                        queued += self.db.upsert_seen(it)
            self.db.set(key, since)
            self.db.set(f"watermark:{p.appid}", since)
            log.info("[%s] backfill queued %d items", p.name, queued)

        watermark = self.db.get(f"watermark:{p.appid}", since)
        newest = watermark
        for sort in ("mostrecent", "lastupdated"):
            for page in range(1, self.cfg.pages_per_poll + 1):
                items, _ = steam.browse_page(p.appid, sort, page, self.cfg.steam_web_api_key)
                fresh = [it for it in items if max(it.time_updated, it.time_created) >= watermark - 3600]
                for it in fresh:
                    queued += self.db.upsert_seen(it)
                    newest = max(newest, it.time_updated, it.time_created)
                if len(fresh) < len(items) or not items:
                    break  # the rest of this listing is older than what we've already covered
                time.sleep(1.5)
        self.db.set(f"watermark:{p.appid}", newest)
        if queued:
            log.info("[%s] queued %d new/updated items", p.name, queued)
        return queued

    # --- processing -------------------------------------------------------------------------------------------
    def process_queue(self, p: games.GameProfile, limit: int = 200) -> int:
        rows = self.db.queued(p.appid, limit)
        if not rows:
            return 0
        # refresh details (title, size, ban status) right before downloading
        fresh = {it.id: it for it in steam.details([r["id"] for r in rows], p.appid)}
        batch, batch_bytes, done = [], 0, 0
        for r in rows:
            it = fresh.get(r["id"])
            if it is None:
                self.db.set_status(p.appid, r["id"], "skipped", "Item was deleted or hidden before we could scan it")
                continue
            self.db.upsert_seen(it)
            it.file_size = it.file_size or r["file_size"] or 0
            if it.file_size > self.cfg.max_item_mb * 1024 * 1024:
                self.db.set_status(p.appid, it.id, "skipped",
                                   f"Larger than MAX_ITEM_MB ({it.file_size // 1048576} MB)")
                continue
            if not it.file_size:  # size unknown: download it on its own so it can't hold up a batch
                done += self._run_batch(p, [it])
                continue
            batch.append(it)
            batch_bytes += it.file_size
            if len(batch) >= BATCH_ITEMS or batch_bytes >= BATCH_BYTES:
                done += self._run_batch(p, batch)
                batch, batch_bytes = [], 0
        if batch:
            done += self._run_batch(p, batch)
        return done

    def _run_batch(self, p: games.GameProfile, items: list[steam.Item], inject_test: bool = False,
                   notify: bool = True) -> int:
        for it in items:
            self.db.set_status(p.appid, it.id, "scanning")
        try:
            results = self.dl.download(p.appid, [it.id for it in items], sum(it.file_size for it in items))
        except LoginRequired as e:
            log.error("%s", e)
            for it in items:
                self.db.set_status(p.appid, it.id, "error", str(e))
            return 0
        finally:
            self.db.set("anon_ok", {str(k): v for k, v in self.dl.anon_ok.items()})
        n = 0
        for it in items:
            res = results.get(it.id)
            if not res or not res.path or not res.path.exists():
                err = res.error if res else "not downloaded"
                log.warning("[%s] %s download failed: %s", p.name, it.id, err)
                self.db.set_status(p.appid, it.id, "error", f"Download failed: {err}")
                continue
            try:
                self.scan_and_record(p, it, res.path, inject_test=inject_test, notify=notify)
                n += 1
            except Exception as e:  # noqa: BLE001 - one bad item mustn't stop the loop
                log.exception("[%s] scan of %s crashed", p.name, it.id)
                self.db.set_status(p.appid, it.id, "error", f"Scanner error: {e}")
            finally:
                self.dl.cleanup(p.appid, it.id)
        self.dl.reset(p.appid)
        return n

    def scan_and_record(self, p: games.GameProfile, it: steam.Item, folder: Path, *, inject_test: bool = False,
                        notify: bool = True) -> ScanResult:
        if inject_test:
            planted = testdata.plant(folder)
            log.warning("[%s] TEST: planted fake malware files %s into %s", p.name, planted, it.id)
        t0 = time.time()
        result = scan_dir(folder, p, self.scanners)
        extra = self._steam_findings(p, it)
        if extra:
            result.findings += extra
            result.verdict, result.score = verdict_for(result.findings)
        details = {"files": result.files_scanned, "bytes": result.bytes_scanned, "sha256": result.sha256,
                   "seconds": round(time.time() - t0, 1), "test_injected": inject_test, "engines": result.engines}
        self.db.upsert_seen(it)
        self.db.save_scan(p.appid, it.id, it.time_updated, result, details, is_test=inject_test)
        log.info("[%s] %s %-10s score=%-3d files=%-4d %s", p.name, it.id, result.verdict.upper(), result.score,
                 result.files_scanned, it.title[:60])
        if result.verdict != "clean" and self.cfg.quarantine_flagged:
            dest = self.cfg.quarantine_dir / str(p.appid) / it.id / str(it.time_updated)
            shutil.rmtree(dest, ignore_errors=True)
            shutil.copytree(folder, dest)
            (dest.parent / "README.txt").write_text(
                "Quarantined by WorkshopGuard for review. These files may be malicious: do not open or run them.\n")
        if notify:
            self.notifier.maybe_send(it.to_dict(), p.name, result.verdict, result.score,
                                     [f.to_dict() for f in result.findings], is_test=inject_test,
                                     previous=self.db.previous_verdict(p.appid, it.id))
        return result

    def _steam_findings(self, p: games.GameProfile, it: steam.Item) -> list[Finding]:
        out = []
        if it.banned:
            out.append(Finding("steam", "high", "steam.banned", f"Steam has banned this item ({it.ban_reason or 'no reason given'})"))
        title = (it.title or "").strip().lower()
        if title and it.creator:
            older = self.db.q("""SELECT id, creator FROM items WHERE appid=? AND lower(trim(title))=? AND creator<>?
                                 AND time_created < ? AND id<>? LIMIT 3""",
                              p.appid, title, it.creator, it.time_created or 2 ** 31, it.id)
            if older:
                out.append(Finding("steam", "medium", "steam.possible_copycat",
                                   "Same title as an older item by a different uploader (copycat re-uploads are a "
                                   "common way to spread malware)", "",
                                   [f"https://steamcommunity.com/sharedfiles/filedetails/?id={r['id']}" for r in older]))
        return out

    # --- loop -------------------------------------------------------------------------------------------------
    def run_forever(self):
        log.info("Watching: %s (every %d min)", ", ".join(f"{g.name} [{g.appid}]" for g in self.cfg.games),
                 self.cfg.poll_minutes)
        while True:
            started = time.time()
            for p in self.cfg.games:
                try:
                    self.discover(p)
                    while self.process_queue(p):
                        pass
                except steam.SteamError as e:
                    log.error("[%s] Steam listing failed: %s", p.name, e)
                except Exception:  # noqa: BLE001
                    log.exception("[%s] poll failed", p.name)
            self.db.set("last_poll", int(time.time()))
            time.sleep(max(30, self.cfg.poll_minutes * 60 - (time.time() - started)))


def details_json(row) -> dict:
    return {**dict(row), "findings": json.loads(row["findings"] or "[]"), "details": json.loads(row["details"] or "{}")}
