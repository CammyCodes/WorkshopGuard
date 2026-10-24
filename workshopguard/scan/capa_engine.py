"""capa (Mandiant): reads an executable and lists what it can do (download files, inject into processes, log keys...).

It complements the .NET analyzer with a second, independent opinion and covers native Windows/Linux programs.
Capabilities alone are common in normal software, so only the clearly hostile ones count for much.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess

from .model import Finding

log = logging.getLogger(__name__)
RULES = os.environ.get("CAPA_RULES", "/opt/capa/rules")
SIGS = os.environ.get("CAPA_SIGS", "/opt/capa/sigs")

# (capa namespace prefix, severity). First match wins. Only plainly hostile capabilities count against a mod:
# checked against real PlateUp mods, capa's broader labels (reflection, Base64, debugger checks, "cryptocurrency
# strings" for a game paid in coins) fire on normal Harmony/KitchenLib mods. Those are kept as low notes.
WEIGHTS: list[tuple[str, str]] = [
    ("collection/keylog", "high"), ("collection/screenshot", "high"), ("collection/browser", "high"),
    ("collection/password", "high"), ("collection/credential", "high"),
    ("persistence/", "high"),
    ("impact/cryptocurrency", "low"),  # matches plain words like "Dash" or "Doge"
    ("impact/", "high"),
    ("communication/c2/", "low"), ("anti-analysis/", "low"), ("collection/", "low"),
    ("host-interaction/process/inject", "low"),
]


def available() -> bool:
    return bool(shutil.which("capa")) and os.path.isdir(RULES)


def _weigh(namespace: str) -> str | None:
    for key, sev in WEIGHTS:
        if namespace.startswith(key):
            return sev
    return None


def analyze(path: str, rel: str, timeout: int = 180) -> tuple[list[Finding], dict]:
    """Run capa on a file on disk. Returns (findings, {"capabilities": [...]})."""
    cmd = ["capa", "-j", "-r", RULES]
    if os.path.isdir(SIGS):
        cmd += ["-s", SIGS]
    cmd.append(path)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return [Finding("capa", "info", "capa.timeout", f"capa took longer than {timeout}s; skipped", rel)], {}
    if p.returncode != 0 or not p.stdout.strip().startswith("{"):
        err = (p.stderr or "").strip().splitlines()[-1:] or ["no output"]
        log.warning("capa failed on %s: %s", rel, err[0][:200])
        return [], {"error": err[0][:300]}
    rules = json.loads(p.stdout).get("rules", {})
    caps, by_sev = [], {}
    for name, r in rules.items():
        meta = r.get("meta", {})
        if meta.get("lib") or (meta.get("namespace") or "").startswith("internal/"):
            continue
        ns = meta.get("namespace") or ""
        caps.append(f"{ns}: {name}" if ns else name)
        sev = _weigh(ns)
        if sev:
            by_sev.setdefault(sev, []).append(name)
    findings = [Finding("capa", sev, f"capa.{sev}", f"capa found {len(names)} {sev}-risk capabilit"
                        f"{'y' if len(names) == 1 else 'ies'}", rel, sorted(names)[:8])
                for sev, names in by_sev.items()]
    return findings, {"capabilities": sorted(caps)}
