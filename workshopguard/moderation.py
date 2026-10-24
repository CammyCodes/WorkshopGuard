"""Publisher mode: a game's own developer can ban bad items from their Workshop for everyone.

Uses the Steamworks publisher Web API (a publisher key from partner.steamgames.com > Users & Permissions > Manage
Groups > Web API key):
  IPublishedFileService/UpdateBanStatus   ban / unban one item (reversible; reason visible to admins only)
  IPublishedFileService/UpdateAppUGCBan   stop an uploader posting Workshop items for the game (reason shown to them)

Deliberately not used: IPublishedFileService/Delete. A ban hides the item and keeps the evidence; deleting can't be
undone, and a scanner can be wrong.

Auto-ban policy (AUTO_BAN):
  off        (default) nothing happens without a person clicking Ban on the dashboard or running `ban`
  confirmed  ban when a known-malware engine agrees: ClamAV, VirusTotal, MetaDefender, MalwareBazaar or a
             high-confidence YARA Forge rule. WorkshopGuard's own heuristics alone never auto-ban.
  malicious  ban on any "malicious" verdict, heuristics included (only if you've watched it for a while)
Test items (selftest, --inject-test) are never banned.
"""

from __future__ import annotations

import json
import logging
import os
import time

import requests

log = logging.getLogger(__name__)

PARTNER_API = os.environ.get("STEAM_PARTNER_API", "https://partner.steam-api.com").rstrip("/")
CONFIRMED_RULES = {"clamav.detected", "virustotal.malicious", "metadefender.malicious",
                   "malwarebazaar.known_malware"}
FOREVER_DAYS = 3650  # UpdateAppUGCBan needs an expiry; ten years is "permanent" in practice


class PublisherError(RuntimeError):
    pass


class SteamPublisher:
    def __init__(self, key: str):
        self.key = key
        self.session = requests.Session()

    def _post(self, method: str, data: dict) -> dict:
        r = self.session.post(f"{PARTNER_API}/IPublishedFileService/{method}/v1/", data={"key": self.key, **data},
                              timeout=30)
        if r.status_code == 403:
            raise PublisherError("Steam refused the publisher key (403). It must be a publisher Web API key from a "
                                 "Steamworks group that has this app and Workshop permissions.")
        if r.status_code >= 400:
            raise PublisherError(f"Steam returned HTTP {r.status_code}: {r.text[:200]}")
        try:
            return r.json()
        except ValueError:
            return {}

    def set_item_ban(self, appid: int, item_id: str, banned: bool, reason: str) -> dict:
        return self._post("UpdateBanStatus", {"appid": appid, "publishedfileid": item_id,
                                              "banned": "true" if banned else "false", "reason": reason[:900]})

    def set_uploader_ban(self, appid: int, steamid: str, days: int, reason: str) -> dict:
        expires = 0 if days <= 0 else int(time.time()) + days * 86400
        return self._post("UpdateAppUGCBan", {"appid": appid, "steamid": steamid, "expiration_time": expires,
                                              "reason": reason[:900]})


def is_confirmed(findings: list[dict]) -> bool:
    """A known-malware engine (not just WorkshopGuard's own heuristics) says this is malware."""
    for f in findings:
        if f["rule"] in CONFIRMED_RULES:
            return True
        if f["rule"].startswith("forge.") and f["severity"] == "critical":
            return True
    return False


def ban_reason(findings: list[dict]) -> str:
    top = [f for f in findings if f["severity"] in ("critical", "high")][:3]
    why = "; ".join(f"{f['description']}" + (f" ({f['file']})" if f.get("file") else "") for f in top)
    return f"WorkshopGuard: {why or 'flagged as malicious'}"


class Moderator:
    def __init__(self, cfg, db, notifier):
        self.cfg, self.db, self.notifier = cfg, db, notifier
        self.api = SteamPublisher(cfg.publisher_key) if cfg.publisher_key else None

    def can_act(self, appid: int) -> bool:
        return bool(self.api) and appid in self.cfg.publisher_apps

    # --- policy, after every scan ----------------------------------------------------------------------------
    def after_scan(self, appid: int, item: dict, verdict: str, findings: list[dict], is_test: bool) -> str | None:
        if is_test or not self.can_act(appid) or self.cfg.auto_ban == "off" or verdict != "malicious":
            return None
        if self.cfg.auto_ban == "confirmed" and not is_confirmed(findings):
            log.info("[%s] %s is malicious by WorkshopGuard's heuristics only: left for a person to review",
                     appid, item["id"])
            return None
        row = self.db.item(appid, item["id"])
        if row and row["moderation"] in ("banned", "cleared"):
            return None  # already handled, or a person said it's fine
        reason = ban_reason(findings)
        ok = self.ban_item(appid, item["id"], reason, by="auto")
        if ok and self.cfg.ban_uploader and item.get("creator"):
            self.ban_uploader(appid, item["id"], item["creator"], by="auto")
        return "banned" if ok else None

    # --- actions (dashboard, CLI, auto) ----------------------------------------------------------------------
    def _log(self, appid, item_id, creator, action, reason, by, ok, response):
        self.db.x("""INSERT INTO moderation(appid,item_id,creator,action,reason,by,at,ok,response)
                     VALUES(?,?,?,?,?,?,?,?,?)""", appid, item_id, creator, action, reason, by, int(time.time()),
                  int(ok), json.dumps(response)[:2000])

    def _require(self, appid: int):
        if not self.api:
            raise PublisherError("Publisher mode is off: set PUBLISHER_KEY in .env")
        if appid not in self.cfg.publisher_apps:
            raise PublisherError(f"App {appid} isn't in PUBLISHER_APPS, so WorkshopGuard won't act on it")

    def ban_item(self, appid: int, item_id: str, reason: str, by: str) -> bool:
        self._require(appid)
        row = self.db.item(appid, item_id)
        creator = row["creator"] if row else ""
        try:
            resp = self.api.set_item_ban(appid, item_id, True, reason)
        except (PublisherError, requests.RequestException) as e:
            self._log(appid, item_id, creator, "ban_item", reason, by, False, {"error": str(e)})
            log.error("Ban of %s failed: %s", item_id, e)
            return False
        self._log(appid, item_id, creator, "ban_item", reason, by, True, resp)
        self.db.x("UPDATE items SET moderation='banned' WHERE appid=? AND id=?", appid, item_id)
        log.warning("BANNED Workshop item %s in app %s (%s): %s", item_id, appid, by, reason)
        self.notifier.moderation(appid, item_id, row["title"] if row else item_id, "banned", reason, by)
        return True

    def unban_item(self, appid: int, item_id: str, by: str) -> bool:
        self._require(appid)
        row = self.db.item(appid, item_id)
        resp = self.api.set_item_ban(appid, item_id, False, f"Unbanned via WorkshopGuard by {by}")
        self._log(appid, item_id, row["creator"] if row else "", "unban_item", "", by, True, resp)
        # a person looked at it and decided it's fine: don't auto-ban this version again
        self.db.x("UPDATE items SET moderation='cleared' WHERE appid=? AND id=?", appid, item_id)
        self.notifier.moderation(appid, item_id, row["title"] if row else item_id, "unbanned", "", by)
        return True

    def ban_uploader(self, appid: int, item_id: str, steamid: str, by: str, days: int | None = None) -> bool:
        self._require(appid)
        days = self.cfg.uploader_ban_days if days is None else days
        days = FOREVER_DAYS if days <= 0 else days
        reason = self.cfg.uploader_ban_reason
        try:
            resp = self.api.set_uploader_ban(appid, steamid, days, reason)
        except (PublisherError, requests.RequestException) as e:
            self._log(appid, item_id, steamid, "ban_uploader", reason, by, False, {"error": str(e)})
            return False
        self._log(appid, item_id, steamid, "ban_uploader", reason, by, True, resp)
        log.warning("BANNED uploader %s from app %s Workshop for %d days (%s)", steamid, appid, days, by)
        return True

    def unban_uploader(self, appid: int, steamid: str, by: str) -> bool:
        self._require(appid)
        resp = self.api.set_uploader_ban(appid, steamid, -1, "")  # -1 -> expiration_time 0 = remove the ban
        self._log(appid, "", steamid, "unban_uploader", "", by, True, resp)
        return True

    def clear(self, appid: int, item_id: str, by: str):
        """Mark a flag as a false alarm: it leaves the review queue and the blocklist, and won't be auto-banned."""
        self.db.x("UPDATE items SET moderation='cleared' WHERE appid=? AND id=?", appid, item_id)
        self._log(appid, item_id, "", "clear", "marked as a false alarm", by, True, {})


def _clean_hashes(db, appid: int) -> set[str]:
    out = set()
    for (d,) in db.q("SELECT details FROM items WHERE appid=? AND status='scanned' AND verdict='clean'", appid):
        out |= set(json.loads(d or "{}").get("sha256", {}).values())
    return out


def blocklist(db, appid: int) -> dict:
    """What a game should refuse to load: items banned through WorkshopGuard, plus the hashes of their flagged files
    so a re-upload of the same payload under a new ID is caught too. Only flagged files are listed, and never a
    file that also ships in a clean item: a bad mod bundling 0Harmony.dll mustn't block every Harmony mod."""
    safe = _clean_hashes(db, appid)
    items = []
    for r in db.q("""SELECT id, title, creator, details, findings FROM items
                     WHERE appid=? AND moderation='banned' ORDER BY id""", appid):
        details = json.loads(r["details"] or "{}")
        flagged = {f["file"] for f in json.loads(r["findings"] or "[]")
                   if f.get("file") and f["severity"] in ("medium", "high", "critical")}
        hashes = {h for path, h in details.get("sha256", {}).items() if path in flagged} - safe
        ban = db.q("""SELECT reason, at FROM moderation WHERE appid=? AND item_id=? AND action='ban_item' AND ok=1
                      ORDER BY rowid DESC LIMIT 1""", appid, r["id"])
        items.append({
            "id": r["id"], "title": r["title"], "creator": r["creator"],
            "banned_at": ban[0]["at"] if ban else None, "reason": ban[0]["reason"] if ban else "",
            "sha256": sorted(hashes),
        })
    return {"appid": appid, "generated": int(time.time()), "items": items,
            "sha256": sorted({h for it in items for h in it["sha256"]})}
