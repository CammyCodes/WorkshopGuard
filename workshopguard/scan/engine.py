"""Walks a downloaded Workshop item and runs every scanner over every file (and inside zip archives)."""

from __future__ import annotations

import hashlib
import io
import logging
import os
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .. import games
from . import dotnet, pe
from .clamav import ClamAV
from .model import Finding, ScanResult, verdict_for
from .virustotal import VirusTotal
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


@dataclass
class Scanners:
    yara: Yara | None = None
    clamav: ClamAV | None = None
    virustotal: VirusTotal | None = None


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
        self.clam_errors = 0
        self.details: dict[str, dict] = {}

    # --- per file -------------------------------------------------------------------------------------------
    def file(self, rel: str, data: bytes, full_size: int, sha256: str, depth: int = 0):
        self.files += 1
        self.bytes += full_size
        self.hashes[rel] = sha256
        name = rel.rsplit("!", 1)[-1].rsplit("/", 1)[-1]
        ext = os.path.splitext(name)[1].lower()
        kind = _magic(data)
        p = self.profile
        add = self.findings.append

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
            sev = "high" if ext not in (".url",) else "medium"
            add(Finding("files", sev, "files.executable_type",
                        f"'{ext}' files can run code on your PC; {p.name} items don't need them", rel))
        elif ext not in p.expected_exts and ext not in p.code_exts and p.expected_exts and kind != "pe":
            self.unexpected.setdefault(ext or "(none)", []).append(rel)

        # --- executables ------------------------------------------------------------------------------------
        dotnet_caps: set[str] = set()
        if kind == "pe":
            pf, info = pe.analyze(data, rel)
            self.findings += pf
            if not p.dlls_expected and ext not in games.EXECUTABLE_EXTS:  # .exe etc. were flagged above
                add(Finding("files", "high", "files.windows_code",
                            f"Windows code ({name}) inside a {p.name} item; the game never loads these", rel))
            elif p.dlls_expected and not info.get("dotnet") and ext == ".dll":
                add(Finding("files", "medium", "files.native_dll",
                            f"Native (non-.NET) DLL in a {p.name} mod; mods are normally .NET", rel))
            if info.get("dotnet"):
                df, summary = dotnet.analyze(data, rel)
                self.findings += df
                self.details[rel] = summary
                dotnet_caps = set(summary.get("capabilities", []))
            if self.sc.virustotal:
                f = self.sc.virustotal.lookup(sha256, rel)
                if f:
                    add(f)

        # --- signature scanners -----------------------------------------------------------------------------
        if self.sc.yara:
            self.findings += self.sc.yara.scan(data, rel, ext, dotnet_caps)
        if self.sc.clamav:
            try:
                sig = self.sc.clamav.scan_bytes(data)
                if sig:
                    add(Finding("clamav", "critical", "clamav.detected", f"ClamAV detected {sig}", rel, [sig]))
            except OSError as e:
                self.clam_errors += 1
                log.warning("ClamAV scan failed for %s: %s", rel, e)

        # --- archives ---------------------------------------------------------------------------------------
        if kind == "zip":
            self.zip(rel, data, depth)
        elif kind in ("rar", "7z", "cab"):
            add(Finding("files", "medium", "files.archive_not_unpacked",
                        f"{kind.upper()} archive: its contents can't be inspected here", rel))

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
        if self.clam_errors:
            self.findings.append(Finding("clamav", "info", "clamav.unavailable",
                                         f"ClamAV could not scan {self.clam_errors} file(s)", ""))
        verdict, score = verdict_for(self.findings)
        return ScanResult(verdict, score, self.findings, self.files, self.bytes, self.hashes)


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
            s.file(rel, data, size, digest)
    return s.finish()
