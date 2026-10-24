"""Runs WorkshopGuard's engines over a changed item, file by file, with results cached per (file hash, name).

Engines on a player's PC: file checks, the .NET mod analyzer, Windows program checks, WorkshopGuard's YARA rules
and YARA Forge's, Microsoft Defender, known-bad hashes, blocklists, and optionally ClamAV, capa and online hash
lookups. Change any engine or rule and `engines_id` changes, so everything is checked again with the new ones.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .. import games
from ..scan.model import Finding, ScanResult, verdict_for
from . import defender

log = logging.getLogger(__name__)
SCAN_VERSION = "gate-1"   # bump when the gate's own checks change meaning
PKG = Path(__file__).resolve().parents[1]
RULES = PKG.parent / "rules"
FULL_SCAN_BYTES = 256 * 1024 * 1024
HEAD_BYTES = 64 * 1024 * 1024
_RULE = re.compile(r"^\s*(?:(?:private|global)\s+)*rule\s+\w+")
_NEEDS_OPENSSL = re.compile(r"\bpe\.(?:number_of_signatures|signatures\b|is_signed\b)")


def _has_openssl() -> bool:
    import yara
    try:
        yara.compile(source="import \"pe\" rule t { condition: pe.number_of_signatures >= 0 }")
        return True
    except yara.SyntaxError:
        return False


def forge_path(home: Path) -> Path:
    """YARA Forge's core rules: downloaded next to the code by scripts/install-gate.ps1 (or into the gate's home)."""
    env = os.environ.get("WG_YARA_FORGE")
    if env:
        return Path(env)
    for p in (home / "rules" / "yara-rules-core.yar", PKG.parent / ".gate" / "rules" / "yara-rules-core.yar"):
        if p.is_file():
            return p
    return PKG.parent / ".gate" / "rules" / "yara-rules-core.yar"


class Scanner:
    def __init__(self, home: Path, cfg, state, appid: int):
        self.home, self.cfg, self.st, self.appid = home, cfg, state, appid
        self.profile = games.profile_for(appid)
        self.forge_path = forge_path(home)
        self.custom = home / "custom-rules"
        self.defender = defender.Defender(exe) if cfg.defender and (exe := defender.find()) else None
        self.engines = self._engines_id()
        self.blocklist: dict[str, str] = {}
        self._sc = None
        self._bad = None
        self.notes: list[str] = []

    # --- versions -----------------------------------------------------------------------------------------------
    def _engines_id(self) -> str:
        h = hashlib.sha256(SCAN_VERSION.encode())
        files = sorted((PKG / "scan").glob("*.py")) + [Path(__file__)] + sorted(RULES.glob("*"))
        if self.custom.is_dir():
            files += sorted(self.custom.rglob("*.yar*"))
        for p in files:
            try:
                h.update(p.name.encode() + b"\0" + p.read_bytes())
            except OSError:
                pass
        if self.cfg.yara_forge and self.forge_path.is_file():
            st = self.forge_path.stat()
            h.update(f"forge:{st.st_size}:{st.st_mtime_ns}".encode())
        h.update(json.dumps([bool(self.defender), self.cfg.clamav, self.cfg.capa, bool(self.cfg.virustotal_key),
                             bool(self.cfg.metadefender_key), bool(self.cfg.malwarebazaar_key)]).encode())
        return h.hexdigest()[:16]

    # --- engines, built only when something needs scanning ------------------------------------------------------
    def scanners(self):
        if self._sc is not None:
            return self._sc
        from ..scan import capa_engine, engine
        from ..scan.clamav import ClamAV
        clam = None
        if self.cfg.clamav:
            host, _, port = self.cfg.clamav.rpartition(":")
            c = ClamAV(host or "127.0.0.1", int(port or 3310))
            if c.ping():
                clam = c
            else:
                self.notes.append(f"ClamAV at {self.cfg.clamav} isn't answering; scanned without it")
        online = []
        if self.cfg.virustotal_key or self.cfg.metadefender_key or self.cfg.malwarebazaar_key:
            from ..scan import online as on
            if self.cfg.malwarebazaar_key:
                online.append(on.MalwareBazaar(self.cfg.malwarebazaar_key))
            if self.cfg.metadefender_key:
                online.append(on.MetaDefender(self.cfg.metadefender_key))
            if self.cfg.virustotal_key:
                online.append(on.VirusTotal(self.cfg.virustotal_key))
        self._sc = engine.Scanners(yara=self._yara(), clamav=clam, capa=self.cfg.capa and capa_engine.available(),
                                   online=online, cache=self.st)
        return self._sc

    def _forge_for_this_yara(self) -> Path:
        """YARA Forge as this YARA build can compile it. Windows yara-python wheels have no OpenSSL, so rules that
        read Authenticode signatures (pe.signatures, pe.number_of_signatures) don't compile; drop just those rules
        (and any rule that depends on one) instead of losing all ~5,000."""
        import yara
        src = self.forge_path
        if not src.is_file():
            return src
        st = src.stat()
        out = self.home / "cache" / f"forge-{st.st_size}-{st.st_mtime_ns}-{yara.__version__}.yar"
        if out.is_file():
            return out
        lines = src.read_text(encoding="utf-8", errors="replace").split("\n")
        starts = [i for i, ln in enumerate(lines) if _RULE.match(ln)]

        def drop(i: int) -> str:
            start = max((s for s in starts if s <= i), default=None)
            if start is None:
                raise ValueError(f"line {i + 1} isn't inside a rule")
            end = next((j for j in range(start, len(lines)) if lines[j].rstrip() == "}"), start)
            name = lines[start].split("rule", 1)[1].split(":")[0].split("{")[0].strip()
            for j in range(start, end + 1):
                lines[j] = ""
            return name

        dropped = [drop(i) for i, ln in enumerate(lines) if _NEEDS_OPENSSL.search(ln)] if not _has_openssl() else []
        for _ in range(200):
            try:
                yara.compile(source="\n".join(lines))
                break
            except yara.SyntaxError as e:
                m = re.search(r"\((\d+)\):", str(e))
                if not m:
                    raise
                dropped.append(drop(int(m.group(1)) - 1))
        out.parent.mkdir(parents=True, exist_ok=True)
        for old in out.parent.glob("forge-*.yar"):
            old.unlink(missing_ok=True)
        out.write_text("\n".join(lines), encoding="utf-8")
        if dropped:
            self.notes.append(f"YARA Forge: {len(dropped)} of {len(starts)} rules need features this YARA build "
                              f"lacks and were skipped")
            log.info("YARA Forge rules skipped: %s", ", ".join(dropped))
        return out

    def _yara(self):
        import yara
        from ..scan import yarascan
        yarascan.FORGE = self._forge_for_this_yara() if self.cfg.yara_forge else self.forge_path
        cache = self.home / "cache" / f"yara-{self.engines}.yarc"
        meta = cache.with_suffix(".json")
        if cache.is_file() and meta.is_file():
            try:
                y = yarascan.Yara.__new__(yarascan.Yara)
                m = json.loads(meta.read_text(encoding="utf-8"))
                y.rules, y.forge, y.sources, y.ignore = yara.load(str(cache)), m["forge"], m["sources"], set(m["ignore"])
                return y
            except (yara.Error, OSError, ValueError, KeyError):
                pass
        t = time.perf_counter()
        y = yarascan.Yara(extra_dir=self.custom if self.custom.is_dir() else None, forge=self.cfg.yara_forge)
        if y.rules:
            cache.parent.mkdir(parents=True, exist_ok=True)
            for old in cache.parent.glob("yara-*.yarc"):
                old.unlink(missing_ok=True)
                old.with_suffix(".json").unlink(missing_ok=True)
            y.rules.save(str(cache))
            meta.write_text(json.dumps({"forge": y.forge, "sources": y.sources, "ignore": sorted(y.ignore)}),
                            encoding="utf-8")
        log.info("YARA rules compiled in %.1fs (%s)", time.perf_counter() - t, ", ".join(y.sources))
        return y

    def engine_names(self) -> list[str]:
        sc = self.scanners()
        names = sc.enabled() + (["defender"] if self.defender else []) + ["known-bad"]
        return names + (["blocklist"] if self.blocklist else [])

    # --- known bad --------------------------------------------------------------------------------------------
    def known_bad(self, it) -> list[Finding]:
        if self._bad is None:
            self._bad = self.st.bad()
        out = []
        for rel, (sha, _) in it.files.items():
            b = self._bad.get(sha)
            if b is not None:
                where = "it was blocked before" if b["item"] == it.key else f"same file as '{b['title']}'"
                out.append(Finding("known-bad", "critical", "gate.known_bad",
                                   f"Known malicious file ({where}: {b['reason']})", rel))
            elif sha in self.blocklist:
                out.append(Finding("blocklist", "critical", "blocklist.listed",
                                   f"On the WorkshopGuard blocklist: {self.blocklist[sha]}", rel))
        return out

    def forget_bad_cache(self) -> None:
        self._bad = None

    # --- one item -----------------------------------------------------------------------------------------------
    def scan(self, it, progress=None) -> ScanResult:
        from ..scan import engine
        sc = self.scanners()
        findings: list[Finding] = list(it.notes) + self.known_bad(it)
        todo, cached = [], 0
        for rel in sorted(it.files):
            sha, _ = it.files[rel]
            hit = self.st.file_findings(sha, _name(rel), self.engines)
            if hit is None:
                todo.append(rel)
            else:
                cached += 1
                findings += [Finding(**{**f, "file": _place(f.get("file", ""), rel)}) for f in hit]
        dproc = self.defender.start(it.path) if self.defender and todo else None
        s = engine._Scan(self.profile, sc)
        fresh: dict[str, list[Finding]] = {}
        for n, rel in enumerate(todo):
            if progress:
                progress(rel, n, len(todo))
            sha, size = it.files[rel]
            path = it.path / rel
            try:
                data = _read(path, size)
            except OSError as e:
                findings.append(Finding("files", "low", "files.unreadable", f"Could not read ({e})", rel))
                continue
            if len(data) == size and hashlib.sha256(data).hexdigest() != sha:
                findings.append(Finding("files", "high", "files.busy",
                                        "This file changed while it was being checked", rel))
                continue
            before = len(s.findings)
            s.file(rel, data, size, sha, disk=path)
            fresh[rel] = s.findings[before:]
        if dproc is not None:
            status, threats, msg = self.defender.result(dproc)
            if status == "detected":
                for threat, fpath in threats:
                    rel = _rel(it.path, fpath)
                    f = Finding("defender", "critical", "defender.detected", f"Microsoft Defender: {threat}", rel,
                                [threat])
                    (fresh.setdefault(rel, []) if rel in fresh else findings).append(f)
            elif status == "error":
                self.notes.append(f"Microsoft Defender couldn't scan {it.title}: {msg}")
                findings.append(Finding("defender", "info", "defender.error", f"Defender couldn't scan: {msg}", ""))
                dproc = "error"
        for rel, fs in fresh.items():
            findings += fs
            if dproc != "error":  # cache only complete answers; a Defender hiccup gets retried next launch
                sha = it.files[rel][0]
                self.st.put_file_findings(sha, _name(rel), self.engines,
                                          [{**f.to_dict(), "file": _unplace(f.file, rel)} for f in fs])
        if s.unexpected:
            ev = [f"{ext}: {len(v)} file(s), e.g. {v[0]}" for ext, v in sorted(s.unexpected.items())][:10]
            findings.append(Finding("files", "info", "files.unexpected_types",
                                    f"File types not normally seen in {self.profile.name} items", "", ev))
        verdict, score = verdict_for(findings)
        res = ScanResult(verdict, score, findings, len(it.files), sum(sz for _, sz in it.files.values()),
                         {r: v[0] for r, v in it.files.items()})
        res.engines = {"scanned": len(todo), "cached": cached}
        return res


def _name(rel: str) -> str:
    return rel.rsplit("/", 1)[-1].lower()


def _place(stored: str, rel: str) -> str:
    """Cached findings are stored relative to their file ('' or '!member'); put them back under this path."""
    return rel + stored if stored.startswith("!") else rel if stored == "" else stored


def _unplace(file: str, rel: str) -> str:
    if file == rel:
        return ""
    if file.startswith(rel + "!"):
        return file[len(rel):]
    return file


def _rel(root: Path, p: str) -> str:
    try:
        return Path(p).resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return p


def _read(path: Path, size: int) -> bytes:
    keep = FULL_SCAN_BYTES if size <= FULL_SCAN_BYTES else HEAD_BYTES
    with open(path, "rb") as fh:
        return fh.read(keep)


# --- blocklists ---------------------------------------------------------------------------------------------------

def load_blocklists(cfg, appid: int, state) -> tuple[dict[str, str], list[str]]:
    """{sha256: reason} from every configured blocklist, fetched in parallel. A source that can't be reached
    falls back to its last good copy (up to 30 days old)."""
    out: dict[str, str] = {}
    notes: list[str] = []

    def fetch(src: str):
        import urllib.request
        loc = src.format(appid=appid)
        if loc.startswith(("http://", "https://")):
            req = urllib.request.Request(loc, headers={"User-Agent": "WorkshopGuard-gate"})
            with urllib.request.urlopen(req, timeout=cfg.blocklist_timeout) as r:  # noqa: S310 - configured URL
                return json.loads(r.read(16 * 1024 * 1024))
        return json.loads(Path(loc).read_text(encoding="utf-8"))

    def one(src: str):
        key = f"blocklist:{src}"
        try:
            data = fetch(src)
            state.set(key, {"at": int(time.time()), "data": data})
            return data, None
        except Exception as e:  # noqa: BLE001 - offline, server down, bad JSON: fall back to the cached copy
            c = state.get(key)
            if c and time.time() - c["at"] < 30 * 86400:
                return c["data"], None
            return None, f"{src}: {e}"

    if not cfg.blocklists:
        return out, notes
    with ThreadPoolExecutor(max_workers=len(cfg.blocklists)) as ex:
        for data, err in ex.map(one, cfg.blocklists):
            if err:
                notes.append(err)
            if not isinstance(data, dict):
                continue
            for item in data.get("items", []):
                why = f"'{item.get('title') or item.get('id')}' {item.get('reason') or 'banned'}".strip()
                for h in item.get("sha256", []):
                    out[str(h).lower()] = why
            for h in data.get("sha256", []):
                out.setdefault(str(h).lower(), "listed as malware")
    return out, notes


def titles(ids: list[str], state, timeout: float = 3.0) -> dict[str, str]:
    """Workshop titles for item IDs, from Steam (keyless), remembered so later launches don't ask again."""
    known: dict[str, str] = state.get("titles", {})
    need = [i for i in ids if i not in known]
    if need:
        import urllib.parse
        import urllib.request
        data = {"itemcount": str(len(need))}
        for n, x in enumerate(need):
            data[f"publishedfileids[{n}]"] = x
        try:
            body = urllib.parse.urlencode(data).encode()
            req = urllib.request.Request(
                "https://api.steampowered.com/ISteamRemoteStorage/GetPublishedFileDetails/v1/", body,
                headers={"User-Agent": "WorkshopGuard-gate"})
            with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
                for d in json.loads(r.read()).get("response", {}).get("publishedfiledetails", []):
                    if d.get("result") == 1 and d.get("title"):
                        known[str(d["publishedfileid"])] = d["title"]
            state.set("titles", known)
        except Exception as e:  # noqa: BLE001 - titles are only cosmetic
            log.info("Couldn't fetch Workshop titles: %s", e)
    return {i: known[i] for i in ids if i in known}

