"""Walks a downloaded Workshop item and runs every enabled engine over every file (and inside zip archives).

Each engine's work is tallied separately, so a scan can show exactly what looked at a mod and what each one said.
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .. import games
from . import capa_engine, dotnet, pe
from .clamav import ClamAV
from .model import Finding, ScanResult, verdict_for
from .online import OnlineEngine
from .yarascan import Yara

log = logging.getLogger(__name__)

FULL_SCAN_BYTES = 256 * 1024 * 1024    # bigger files: hash all, deep-scan the first part
HEAD_BYTES = 64 * 1024 * 1024
ZIP_MAX_DEPTH = 3
ZIP_MAX_MEMBERS = 5000
ZIP_MAX_TOTAL = 1024 * 1024 * 1024
ZIP_MAX_RATIO = 200
MAGIC = {
    b"\x7fELF": "elf", b"\xcf\xfa\xed\xfe": "macho", b"\xfe\xed\xfa\xcf": "macho", b"PK\x03\x04": "zip",
    b"Rar!": "rar", b"7z\xbc\xaf": "7z", b"MSCF": "cab", b"\xd0\xcf\x11\xe0": "ole", b"L\x00\x00\x00": "lnk",
    b"#!": "script",
}
SAFE_LOOKING = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".txt", ".json", ".xml", ".wav", ".ogg", ".mp3", ".dds",
                ".tga", ".ff", ".bundle", ".assets", ".pdf", ".ini", ".cfg"}
RISKY_KINDS = {"pe", "elf", "macho", "zip", "rar", "7z", "cab", "ole", "lnk", "script"}

ENGINES = {  # id: label, in the order reports list them
    "files": "File checks",
    "dotnet": ".NET mod analysis",
    "pe": "Windows program analysis",
    "yara": "YARA: WorkshopGuard rules",
    "yara-forge": "YARA Forge community rules",
    "clamav": "ClamAV antivirus",
    "capa": "capa capability analysis (Mandiant)",
    "virustotal": "VirusTotal (~70 engines)",
    "metadefender": "MetaDefender (~20 engines)",
    "malwarebazaar": "MalwareBazaar known malware",
}
CACHE_DAYS = {"capa": 365, "known": 7, "unknown": 1}


@dataclass
class Scanners:
    yara: Yara | None = None
    clamav: ClamAV | None = None
    capa: bool = False
    online: list[OnlineEngine] = field(default_factory=list)
    cache: object | None = None  # db.DB: cache_get / cache_put by (engine, sha256)

    def enabled(self) -> list[str]:
        out = ["files", "dotnet", "pe"]
        if self.yara:
            out.append("yara")
            if self.yara.forge:
                out.append("yara-forge")
        if self.clamav:
            out.append("clamav")
        if self.capa:
            out.append("capa")
        out += [e.name for e in self.online]
        return out


def _magic(data: bytes) -> str:
    if pe.is_pe(data):
        return "pe"
    for m, kind in MAGIC.items():
        if data.startswith(m):
            return kind
    return ""


class _Scan:
    def __init__(self, profile: games.GameProfile, sc: Scanners):
        self.profile, self.sc = profile, sc
        self.findings: list[Finding] = []
        self.hashes: dict[str, str] = {}
        self.files = 0
        self.bytes = 0
        self.unexpected: dict[str, list[str]] = {}
        self.details: dict[str, dict] = {}
        self.engines = {e: {"label": ENGINES[e], "files": 0, "detections": 0, "notes": 0, "unknown": 0, "errors": 0}
                        for e in sc.enabled()}

    def tally(self, engine: str, findings: list[Finding] = (), *, status: str = ""):
        e = self.engines[engine]
        e["files"] += 1
        if any(f.severity in ("high", "critical") for f in findings) or status == "detected":
            e["detections"] += 1
        elif any(f.severity == "medium" for f in findings):
            e["notes"] += 1
        if status == "unknown":
            e["unknown"] += 1
        if status == "error":
            e["errors"] += 1
        self.findings += findings

    # --- cache for slow/online engines: same file (e.g. Harmony's DLLs) in 50 mods = one lookup --------------
    def cached(self, engine: str, sha: str, rel: str, run):
        c = self.sc.cache
        hit = c.cache_get(engine, sha) if c else None
        if hit is None:
            status, findings = run()
            if c and status != "error":
                days = CACHE_DAYS["capa"] if engine == "capa" else CACHE_DAYS["unknown" if status == "unknown" else "known"]
                c.cache_put(engine, sha, {"status": status, "findings": [f.to_dict() for f in findings]}, days)
            return status, findings
        return hit["status"], [Finding(**{**f, "file": rel}) for f in hit["findings"]]

    # --- per file -------------------------------------------------------------------------------------------
    def file(self, rel: str, data: bytes, full_size: int, sha256: str, depth: int = 0, disk: Path | None = None):
        self.files += 1
        self.bytes += full_size
        self.hashes[rel] = sha256
        name = rel.rsplit("!", 1)[-1].rsplit("/", 1)[-1]
        ext = os.path.splitext(name)[1].lower()
        kind = _magic(data)
        p = self.profile
        found: list[Finding] = []
        add = found.append

        if full_size > len(data):
            add(Finding("files", "info", "files.partial", f"Large file: deep-scanned the first "
                        f"{len(data) // (1024 * 1024)} MB of {full_size // (1024 * 1024)} MB", rel))

        # --- file names and types ---------------------------------------------------------------------------
        parts = name.lower().split(".")
        if len(parts) >= 3 and f".{parts[-1]}" in games.EXECUTABLE_EXTS and f".{parts[-2]}" in SAFE_LOOKING:
            add(Finding("files", "critical", "files.double_extension",
                        f"Disguised file name: '{name}' pretends to be .{parts[-2]} but is .{parts[-1]}", rel))
        if kind == "pe" and ext in SAFE_LOOKING:
            add(Finding("files", "critical", "files.disguised_executable",
                        f"A Windows program hidden under a {ext} name", rel))
        if kind in ("elf", "macho") and ext not in (".so", ".dylib"):
            add(Finding("files", "high", "files.unix_executable", f"Contains a {kind.upper()} executable", rel))
        if ext in games.EXECUTABLE_EXTS and ext not in p.code_exts and ext not in p.expected_exts:
            add(Finding("files", "high" if ext != ".url" else "medium", "files.executable_type",
                        f"'{ext}' files can run code on your PC; {p.name} items don't need them", rel))
        elif ext not in p.expected_exts and ext not in p.code_exts and p.expected_exts and kind != "pe":
            self.unexpected.setdefault(ext or "(none)", []).append(rel)
        if kind == "pe":
            if not p.dlls_expected and ext not in games.EXECUTABLE_EXTS:
                add(Finding("files", "high", "files.windows_code",
                            f"Windows code ({name}) inside a {p.name} item; the game never loads these", rel))
        if kind in ("rar", "7z", "cab"):
            add(Finding("files", "medium", "files.archive_not_unpacked",
                        f"{kind.upper()} archive: its contents can't be inspected here", rel))
        self.tally("files", found)

        # --- executables ------------------------------------------------------------------------------------
        dotnet_caps: set[str] = set()
        if kind == "pe":
            pf, info = pe.analyze(data, rel)
            if p.dlls_expected and not info.get("dotnet") and ext == ".dll":
                pf.append(Finding("pe", "medium", "files.native_dll",
                                  f"Native (non-.NET) DLL in a {p.name} mod; mods are normally .NET", rel))
            self.tally("pe", pf)
            if info.get("dotnet"):
                df, summary = dotnet.analyze(data, rel)
                self.tally("dotnet", df)
                self.details[rel] = summary
                dotnet_caps = set(summary.get("capabilities", []))

        if self.sc.capa and kind in ("pe", "elf"):
            def run_capa():
                if disk is not None and full_size == len(data):
                    f, info = capa_engine.analyze(str(disk), rel)
                else:
                    with tempfile.NamedTemporaryFile(suffix=ext or ".bin", dir="/tmp" if os.path.isdir("/tmp") else None) as t:
                        t.write(data)
                        t.flush()
                        f, info = capa_engine.analyze(t.name, rel)
                if info.get("error"):
                    return "error", []  # not cached, and shown as an error rather than a pass
                return ("detected" if any(x.severity in ("high", "critical") for x in f) else "clean"), f
            status, cf = self.cached("capa", sha256, rel, run_capa)
            self.tally("capa", cf, status=status)

        # --- signature engines ------------------------------------------------------------------------------
        if self.sc.yara:
            ours, forge = self.sc.yara.scan(data, rel, ext, dotnet_caps)
            self.tally("yara", ours)
            if self.sc.yara.forge:
                self.tally("yara-forge", forge)
        if self.sc.clamav:
            try:
                sig = self.sc.clamav.scan_bytes(data)
                self.tally("clamav", [Finding("clamav", "critical", "clamav.detected", f"ClamAV detected {sig}", rel,
                                              [sig])] if sig else [])
            except OSError as e:
                log.warning("ClamAV scan failed for %s: %s", rel, e)
                self.tally("clamav", status="error")

        # --- online multi-engine lookups (executables, scripts, archives, anything out of place) -------------
        risky = kind in RISKY_KINDS or ext in games.EXECUTABLE_EXTS or (p.expected_exts and ext not in p.expected_exts
                                                                       and ext not in p.code_exts)
        if risky:
            for eng in self.sc.online:
                def run(eng=eng):
                    status, f = eng.check(sha256, data, name, rel)
                    return status, [f] if f else []
                status, of = self.cached(eng.name, sha256, rel, run)
                self.tally(eng.name, of, status=status)

        # --- archives ---------------------------------------------------------------------------------------
        if kind == "zip":
            self.zip(rel, data, depth)

    def zip(self, rel: str, data: bytes, depth: int):
        if depth >= ZIP_MAX_DEPTH:
            self.findings.append(Finding("files", "medium", "files.nested_archives", "Archives nested too deep", rel))
            return
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as e:
            self.findings.append(Finding("files", "low", "files.bad_zip", f"Corrupt zip ({e})", rel))
            return
        infos = zf.infolist()
        if len(infos) > ZIP_MAX_MEMBERS:
            self.findings.append(Finding("files", "medium", "files.zip_too_many", f"{len(infos)} files in zip", rel))
            infos = infos[:ZIP_MAX_MEMBERS]
        total = 0
        for zi in infos:
            if zi.is_dir():
                continue
            member = f"{rel}!{zi.filename}"
            if zi.flag_bits & 0x1:
                self.findings.append(Finding("files", "high", "files.encrypted_archive",
                                             "Password-protected file inside an archive (hides it from scanners)",
                                             member))
                continue
            if zi.compress_size and zi.file_size / max(zi.compress_size, 1) > ZIP_MAX_RATIO and zi.file_size > 1 << 26:
                self.findings.append(Finding("files", "high", "files.zip_bomb", "Zip bomb (absurd compression)", member))
                continue
            total += zi.file_size
            if total > ZIP_MAX_TOTAL:
                self.findings.append(Finding("files", "low", "files.zip_truncated", "Zip too big to unpack fully", rel))
                break
            try:
                with zf.open(zi) as fh:
                    blob = fh.read(FULL_SCAN_BYTES)
            except Exception as e:  # noqa: BLE001
                self.findings.append(Finding("files", "low", "files.zip_member_error", f"Can't read ({e})", member))
                continue
            self.file(member, blob, zi.file_size, hashlib.sha256(blob).hexdigest(), depth + 1)

    def finish(self) -> ScanResult:
        if self.unexpected:
            ev = [f"{ext}: {len(v)} file(s), e.g. {v[0]}" for ext, v in sorted(self.unexpected.items())][:10]
            self.findings.append(Finding("files", "info", "files.unexpected_types",
                                         f"File types not normally seen in {self.profile.name} items", "", ev))
        clam = self.engines.get("clamav")
        if clam and clam["errors"]:
            self.findings.append(Finding("clamav", "info", "clamav.unavailable",
                                         f"ClamAV could not scan {clam['errors']} file(s)", ""))
        verdict, score = verdict_for(self.findings)
        return ScanResult(verdict, score, self.findings, self.files, self.bytes, self.hashes, self.engines)


def _read(path: Path) -> tuple[bytes, int, str]:
    """Read up to FULL_SCAN_BYTES for scanning (head only for huge files) and hash the whole file."""
    size = path.stat().st_size
    h = hashlib.sha256()
    keep = FULL_SCAN_BYTES if size <= FULL_SCAN_BYTES else HEAD_BYTES
    buf = bytearray()
    with path.open("rb") as fh:
        while chunk := fh.read(8 * 1024 * 1024):
            h.update(chunk)
            if len(buf) < keep:
                buf += chunk[: keep - len(buf)]
    return bytes(buf), size, h.hexdigest()


def scan_dir(root: Path, profile: games.GameProfile, scanners: Scanners) -> ScanResult:
    s = _Scan(profile, scanners)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in sorted(filenames) + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]:
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            if full.is_symlink():
                s.findings.append(Finding("files", "medium", "files.symlink",
                                          f"Link pointing to {os.readlink(full)!s:.120}", rel))
                continue
            try:
                data, size, digest = _read(full)
            except OSError as e:
                s.findings.append(Finding("files", "low", "files.unreadable", f"Could not read ({e})", rel))
                continue
            s.file(rel, data, size, digest, disk=full)
    return s.finish()
