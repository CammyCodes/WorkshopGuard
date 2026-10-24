"""YARA: WorkshopGuard's own rules (rules/), YARA Forge's community ruleset, and any *.yar in EXTRA_RULES_DIR."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import yara

from .model import Finding, SEVERITIES

log = logging.getLogger(__name__)
BUILTIN = Path(__file__).resolve().parents[2] / "rules"
# YARA Forge "core": thousands of community rules for known malware families, tuned for few false alarms.
FORGE = Path(os.environ.get("YARA_FORGE", "/opt/yara-forge/yara-rules-core.yar"))
FORGE_IGNORE = BUILTIN / "forge_ignore.txt"


def _readable(b: bytes) -> str:
    """Matched bytes as text: UTF-16 strings (common in .NET) decoded, binary escaped."""
    if len(b) >= 4 and b[1::2].count(0) >= len(b) // 2 - 1:
        b = b.decode("utf-16-le", "replace").encode("utf-8")
    text = b.decode("utf-8", "replace")
    return "".join(c if c.isprintable() else "." for c in text)[:100]


def _forge_severity(meta: dict) -> str:
    """YARA Forge scores rules 0-100 by how sure a match is."""
    score = int(meta.get("score", 60) or 60)
    return "critical" if score >= 80 else "high" if score >= 60 else "medium"


class Yara:
    def __init__(self, extra_dir: Path | None = None, forge: bool = True):
        files: dict[str, str] = {}
        for d in (BUILTIN, extra_dir):
            if d and d.is_dir():
                for p in sorted(d.rglob("*.yar")) + sorted(d.rglob("*.yara")):
                    files[f"{d.name}/{p.relative_to(d).as_posix()}"] = str(p)
        good: dict[str, str] = {}
        for ns, path in files.items():  # one bad user rule mustn't disable the rest
            try:
                yara.compile(filepath=path)
                good[ns] = path
            except yara.Error as e:
                log.error("Skipping YARA file %s: %s", path, e)
        self.forge = False
        if forge and FORGE.is_file():
            try:
                yara.compile(filepath=str(FORGE))
                good["forge"] = str(FORGE)
                self.forge = True
            except yara.Error as e:
                log.error("YARA Forge rules didn't compile, skipping them: %s", e)
        self.ignore = set()
        if FORGE_IGNORE.is_file():
            self.ignore = {ln.split("#")[0].strip() for ln in FORGE_IGNORE.read_text().splitlines()} - {""}
        self.sources = list(good)
        self.rules = yara.compile(filepaths=good) if good else None
        log.info("YARA: %d rule files loaded%s", len(good), " (incl. YARA Forge)" if self.forge else "")

    def scan(self, data: bytes, path: str, ext: str,
             skip_caps: set[str] | frozenset = frozenset()) -> tuple[list[Finding], list[Finding]]:
        """Returns (WorkshopGuard/custom rule findings, YARA Forge findings)."""
        if not self.rules:
            return [], []
        ours, forge = [], []
        try:
            matches = self.rules.match(data=data, timeout=60)
        except yara.Error as e:
            return [Finding("yara", "low", "yara.error", f"YARA could not scan this file ({e})", path)], []
        for m in matches:
            meta = m.meta
            ev = [_readable(bytes(inst.matched_data[:160])) for s in m.strings[:4] for inst in s.instances[:1]]
            if m.namespace == "forge":
                if m.rule in self.ignore:
                    continue
                desc = str(meta.get("description") or m.rule)
                forge.append(Finding("yara-forge", _forge_severity(meta), f"forge.{m.rule}",
                                     f"Community rule {m.rule}: {desc}"[:300], path, ev))
                continue
            sev = str(meta.get("severity", "high")).lower()
            sev = sev if sev in SEVERITIES else "high"
            only = str(meta.get("only_ext", "")).lower()
            if only and ext not in only.split(","):
                continue
            if skip_caps and set(str(meta.get("dotnet_cap", "")).split(",")) & skip_caps:
                continue  # the .NET analyzer already explained this, with better evidence
            ours.append(Finding("yara", sev, f"yara.{m.rule}", str(meta.get("description", m.rule)), path, ev))
        return ours, forge
