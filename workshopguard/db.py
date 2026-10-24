"""SQLite state: what we've seen, what we've scanned, and at which item version."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
    appid INTEGER NOT NULL,
    id TEXT NOT NULL,
    title TEXT, creator TEXT, preview_url TEXT,
    time_created INTEGER, time_updated INTEGER, file_size INTEGER,
    banned INTEGER DEFAULT 0, ban_reason TEXT,
    status TEXT DEFAULT 'queued',        -- queued | scanning | scanned | error | skipped
    verdict TEXT,                         -- clean | suspicious | malicious
    score INTEGER,
    scanned_version INTEGER,              -- time_updated of the version we scanned
    scanned_at INTEGER,
    error TEXT,
    findings TEXT,                        -- JSON list
    details TEXT,                         -- JSON (files, hashes, ...)
    is_test INTEGER DEFAULT 0,
    first_seen INTEGER,
    PRIMARY KEY (appid, id)
);
CREATE TABLE IF NOT EXISTS scans (
    rowid INTEGER PRIMARY KEY AUTOINCREMENT,
    appid INTEGER, id TEXT, version INTEGER, verdict TEXT, score INTEGER, at INTEGER, findings TEXT
);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS cache (engine TEXT, sha256 TEXT, value TEXT, expires INTEGER, PRIMARY KEY (engine, sha256));
CREATE TABLE IF NOT EXISTS local_items (path TEXT PRIMARY KEY, fingerprint TEXT, verdict TEXT, scanned_at INTEGER);
CREATE INDEX IF NOT EXISTS items_status ON items(status);
CREATE INDEX IF NOT EXISTS items_verdict ON items(verdict);
"""


class DB:
    def __init__(self, path: Path):
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self.lock = threading.Lock()

    def q(self, sql: str, *args):
        with self.lock:
            return self.conn.execute(sql, args).fetchall()

    def x(self, sql: str, *args):
        with self.lock:
            self.conn.execute(sql, args)

    # --- kv ---
    def get(self, k: str, default=None):
        r = self.q("SELECT v FROM kv WHERE k=?", k)
        return json.loads(r[0]["v"]) if r else default

    def set(self, k: str, v):
        self.x("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", k, json.dumps(v))

    # --- per-file engine cache (capa, online lookups) ---
    def cache_get(self, engine: str, sha256: str):
        r = self.q("SELECT value FROM cache WHERE engine=? AND sha256=? AND expires>?", engine, sha256, int(time.time()))
        return json.loads(r[0]["value"]) if r else None

    def cache_put(self, engine: str, sha256: str, value, days: float):
        self.x("INSERT OR REPLACE INTO cache(engine,sha256,value,expires) VALUES(?,?,?,?)",
               engine, sha256, json.dumps(value), int(time.time() + days * 86400))

    # --- items ---
    def upsert_seen(self, it) -> bool:
        """Record an item from a listing. Returns True if it needs a (re)scan."""
        row = self.q("SELECT time_updated, scanned_version, status FROM items WHERE appid=? AND id=?", it.appid, it.id)
        if not row:
            self.x("""INSERT INTO items(appid,id,title,creator,preview_url,time_created,time_updated,file_size,banned,
                      ban_reason,status,first_seen) VALUES(?,?,?,?,?,?,?,?,?,?, 'queued', ?)""",
                   it.appid, it.id, it.title, it.creator, it.preview_url, it.time_created, it.time_updated,
                   it.file_size, int(it.banned), it.ban_reason, int(time.time()))
            return True
        # GetPublishedFileDetails sometimes says file_size 0 when the listing knew the real size: keep the known one
        self.x("""UPDATE items SET title=?, creator=?, preview_url=?, time_updated=?,
                  file_size=CASE WHEN ? > 0 THEN ? ELSE file_size END, banned=?, ban_reason=?
                  WHERE appid=? AND id=?""",
               it.title, it.creator, it.preview_url, it.time_updated, it.file_size, it.file_size, int(it.banned),
               it.ban_reason, it.appid, it.id)
        r = row[0]
        if r["scanned_version"] is not None and it.time_updated > r["scanned_version"] and r["status"] != "queued":
            self.x("UPDATE items SET status='queued' WHERE appid=? AND id=?", it.appid, it.id)
            return True
        return False

    def queued(self, appid: int, limit: int = 50) -> list[sqlite3.Row]:
        """Queued items, plus failed ones again after 6 hours (Steam hiccups, timeouts)."""
        return self.q("""SELECT * FROM items WHERE appid=? AND (status='queued' OR (status='error' AND scanned_at < ?))
                         ORDER BY time_updated DESC LIMIT ?""", appid, int(time.time()) - 6 * 3600, limit)

    def set_status(self, appid: int, id_: str, status: str, error: str = ""):
        self.x("UPDATE items SET status=?, error=?, scanned_at=? WHERE appid=? AND id=?",
               status, error, int(time.time()), appid, id_)

    def save_scan(self, appid: int, id_: str, version: int, result, details: dict, is_test: bool = False):
        findings = json.dumps([f.to_dict() for f in result.findings])
        now = int(time.time())
        self.x("""UPDATE items SET status='scanned', verdict=?, score=?, scanned_version=?, scanned_at=?, error='',
                  findings=?, details=?, is_test=? WHERE appid=? AND id=?""",
               result.verdict, result.score, version, now, findings, json.dumps(details), int(is_test), appid, id_)
        self.x("INSERT INTO scans(appid,id,version,verdict,score,at,findings) VALUES(?,?,?,?,?,?,?)",
               appid, id_, version, result.verdict, result.score, now, findings)

    def previous_verdict(self, appid: int, id_: str) -> str | None:
        r = self.q("SELECT verdict FROM scans WHERE appid=? AND id=? ORDER BY rowid DESC LIMIT 1 OFFSET 1", appid, id_)
        return r[0]["verdict"] if r else None

    def item(self, appid: int, id_: str):
        r = self.q("SELECT * FROM items WHERE appid=? AND id=?", appid, id_)
        return r[0] if r else None

    def stats(self) -> dict:
        out = {}
        for r in self.q("""SELECT appid, status, COALESCE(verdict,'') v, is_test, COUNT(*) n FROM items
                           GROUP BY appid, status, v, is_test"""):
            g = out.setdefault(r["appid"], {"total": 0})
            g["total"] += r["n"]
            key = "test" if r["is_test"] else r["v"] if r["status"] == "scanned" else r["status"]
            g[key] = g.get(key, 0) + r["n"]
        return out
