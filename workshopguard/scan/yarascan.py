"""YARA rules: the bundled rules/ folder plus any *.yar the user drops into EXTRA_RULES_DIR."""

from __future__ import annotations

import logging
from pathlib import Path

import yara

from .model import Finding, SEVERITIES

log = logging.getLogger(__name__)
BUILTIN = Path(__file__).resolve().parents[2] / "rules"


def _readable(b: bytes) -> str:
    """Matched bytes as text: UTF-16 strings (common in .NET) decoded, binary escaped."""
    if len(b) >= 4 and b[1::2].count(0) >= len(b) // 2 - 1:
        b = b.decode("utf-16-le", "replace").encode("utf-8")
    text = b.decode("utf-8", "replace")
    return "".join(c if c.isprintable() else "." for c in text)[:100]


class Yara:
    def __init__(self, extra_dir: Path | None = None):
        files: dict[str, str] = {}
        for d in (BUILTIN, extra_dir):
            if d and d.is_dir():
                for p in sorted(d.rglob("*.yar")) + sorted(d.rglob("*.yara")):
                    files[f"{d.name}/{p.relative_to(d).as_posix()}"] = str(p)
        self.sources = list(files)
        good: dict[str, str] = {}
        for ns, path in files.items():  # one bad user rule mustn't disable the rest
            try:
                yara.compile(filepath=path)
                good[ns] = path
            except yara.Error as e:
                log.error("Skipping YARA file %s: %s", path, e)
        self.rules = yara.compile(filepaths=good) if good else None
        log.info("YARA: %d rule files loaded", len(good))

    def scan(self, data: bytes, path: str, ext: str, skip_caps: set[str] | frozenset = frozenset()) -> list[Finding]:
        if not self.rules:
            return []
        out = []
        try:
            matches = self.rules.match(data=data, externals={}, timeout=60)
        except yara.Error as e:
            return [Finding("yara", "low", "yara.error", f"YARA could not scan this file ({e})", path)]
        for m in matches:
            meta = m.meta
            sev = str(meta.get("severity", "high")).lower()
            sev = sev if sev in SEVERITIES else "high"
            only = str(meta.get("only_ext", "")).lower()
            if only and ext not in only.split(","):
                continue
            if skip_caps and set(str(meta.get("dotnet_cap", "")).split(",")) & skip_caps:
                continue  # the .NET analyzer already explained this, with better evidence
            ev = []
            for s in m.strings[:4]:
                for inst in s.instances[:1]:
                    ev.append(_readable(bytes(inst.matched_data[:160])))
            out.append(Finding("yara", sev, f"yara.{m.rule}", str(meta.get("description", m.rule)), path, ev))
        return out
