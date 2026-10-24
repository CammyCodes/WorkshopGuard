"""What the gate remembers between launches, in one SQLite file in the player's profile."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS items(
    key TEXT PRIMARY KEY,           -- ws:<appid>:<id> | local:<appid>:<name>
    appid INTEGER, kind TEXT, path TEXT, title TEXT,
    digest TEXT,                    -- hash of every (path, sha256) in the item
    engines TEXT,                   -- which engine/rule versions gave the verdict
    verdict TEXT, score INTEGER, findings TEXT, scanned_at INTEGER,
    decision TEXT DEFAULT '',       -- '' | allowed | blocked: the player's call on a flagged digest
    decision_digest TEXT DEFAULT '',
    status TEXT DEFAULT 'active',   -- active | quarantined
    quarantine TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS files(key TEXT, rel TEXT, sha256 TEXT, size INTEGER, PRIMARY KEY(key, rel));
CREATE INDEX IF NOT EXISTS files_sha ON files(sha256);
-- per-file engine results: the same 0Harmony.dll in 30 mods is scanned once
CREATE TABLE IF NOT EXISTS filecache(sha256 TEXT, name TEXT, engines TEXT, findings TEXT, at INTEGER,
                                     PRIMARY KEY(sha256, name, engines));
-- files that made an item malicious; a re-download of the same payload is blocked without a scan
CREATE TABLE IF NOT EXISTS bad(sha256 TEXT PRIMARY KEY, item TEXT, title TEXT, reason TEXT, at INTEGER);
CREATE TABLE IF NOT EXISTS game(appid INTEGER PRIMARY KEY, buildid TEXT, files TEXT, verified_at INTEGER,
                                tampered TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS ecache(engine TEXT, sha256 TEXT, value TEXT, expires INTEGER, PRIMARY KEY(engine, sha256));
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS launches(at INTEGER, appid INTEGER, ms INTEGER, items INTEGER, scanned INTEGER,
                                    outcome TEXT, detail TEXT);
"""


class State:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.c = sqlite3.connect(str(path), timeout=30, check_same_thread=False, isolation_level=None)
        self.c.row_factory = sqlite3.Row
        self.lock = threading.RLock()  # the scan thread and the launcher share one connection
        self.c.execute("PRAGMA journal_mode=WAL")
        self.c.execute("PRAGMA synchronous=NORMAL")
        self.c.executescript(SCHEMA)

    def q(self, sql: str, *a) -> list[sqlite3.Row]:
        with self.lock:
            return self.c.execute(sql, a).fetchall()

    def x(self, sql: str, *a) -> None:
        with self.lock:
            self.c.execute(sql, a)

    def many(self, sql: str, rows) -> None:
        with self.lock:
            self.c.executemany(sql, rows)

    def tx(self):
        return _Tx(self)

    # --- items --------------------------------------------------------------------------------------------------
    def item(self, key: str) -> sqlite3.Row | None:
        r = self.q("SELECT * FROM items WHERE key=?", key)
        return r[0] if r else None

    def items(self, appid: int) -> list[sqlite3.Row]:
        return self.q("SELECT * FROM items WHERE appid=? ORDER BY kind, title", appid)

    def save_item(self, it, res, engines: str) -> None:
        with self.tx():
            self.x("""INSERT INTO items(key, appid, kind, path, title, digest, engines, verdict, score, findings,
                                        scanned_at, status)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?, 'active')
                      ON CONFLICT(key) DO UPDATE SET path=excluded.path, title=excluded.title,
                        digest=excluded.digest, engines=excluded.engines, verdict=excluded.verdict,
                        score=excluded.score, findings=excluded.findings, scanned_at=excluded.scanned_at,
                        status='active', quarantine=''""",
                   it.key, it.appid, it.kind, str(it.path), it.title, it.digest, engines, res.verdict, res.score,
                   json.dumps([f.to_dict() for f in res.findings]), int(time.time()))
            self.x("DELETE FROM files WHERE key=?", it.key)
            self.many("INSERT INTO files(key, rel, sha256, size) VALUES(?,?,?,?)",
                               [(it.key, rel, sha, size) for rel, (sha, size) in it.files.items()])

    def decide(self, key: str, decision: str, digest: str) -> None:
        self.x("UPDATE items SET decision=?, decision_digest=? WHERE key=?", decision, digest, key)

    def clean_hashes(self) -> set[str]:
        return {r[0] for r in self.q("""SELECT f.sha256 FROM files f JOIN items i ON i.key=f.key
                                         WHERE i.verdict='clean'""")}

    def add_bad(self, rows: list[tuple[str, str, str, str]]) -> None:
        now = int(time.time())
        self.many("INSERT OR REPLACE INTO bad(sha256, item, title, reason, at) VALUES(?,?,?,?,?)",
                           [(*r, now) for r in rows])

    def bad(self) -> dict[str, sqlite3.Row]:
        return {r["sha256"]: r for r in self.q("SELECT * FROM bad")}

    # --- per-file engine cache ----------------------------------------------------------------------------------
    def file_findings(self, sha: str, name: str, engines: str) -> list[dict] | None:
        r = self.q("SELECT findings FROM filecache WHERE sha256=? AND name=? AND engines=?", sha, name, engines)
        return json.loads(r[0][0]) if r else None

    def put_file_findings(self, sha: str, name: str, engines: str, findings: list[dict]) -> None:
        self.x("INSERT OR REPLACE INTO filecache(sha256, name, engines, findings, at) VALUES(?,?,?,?,?)",
               sha, name, engines, json.dumps(findings), int(time.time()))

    # --- engine.Scanners cache interface (online lookups) -------------------------------------------------------
    def cache_get(self, engine: str, sha: str):
        r = self.q("SELECT value FROM ecache WHERE engine=? AND sha256=? AND expires>?", engine, sha, int(time.time()))
        return json.loads(r[0][0]) if r else None

    def cache_put(self, engine: str, sha: str, value, days: float) -> None:
        self.x("INSERT OR REPLACE INTO ecache(engine, sha256, value, expires) VALUES(?,?,?,?)",
               engine, sha, json.dumps(value), int(time.time() + days * 86400))

    # --- misc ---------------------------------------------------------------------------------------------------
    def get(self, k: str, default=None):
        r = self.q("SELECT v FROM kv WHERE k=?", k)
        return json.loads(r[0][0]) if r else default

    def set(self, k: str, v) -> None:
        self.x("INSERT OR REPLACE INTO kv(k, v) VALUES(?,?)", k, json.dumps(v))

    def log_launch(self, appid: int, ms: int, items: int, scanned: int, outcome: str, detail: str = "") -> None:
        self.x("INSERT INTO launches VALUES(?,?,?,?,?,?,?)", int(time.time()), appid, ms, items, scanned, outcome,
               detail)
        self.x("DELETE FROM launches WHERE rowid NOT IN (SELECT rowid FROM launches ORDER BY at DESC LIMIT 500)")


class _Tx:
    def __init__(self, st: State):
        self.st = st

    def __enter__(self):
        self.st.lock.acquire()
        self.st.c.execute("BEGIN")

    def __exit__(self, et, *_):
        try:
            self.st.c.execute("ROLLBACK" if et else "COMMIT")
        finally:
            self.st.lock.release()
