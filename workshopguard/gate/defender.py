"""Microsoft Defender, through its command-line scanner. Built into Windows, signatures updated daily, ~0.5 s a
folder. Run with -DisableRemediation so Defender only reports: the gate quarantines the whole item itself."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

_THREAT = re.compile(r"^\s*Threat\s*:\s*(.+?)\s*$")
_FILE = re.compile(r"^\s*file\s*:\s*(.+?)\s*$", re.I)


def find() -> Path | None:
    env = os.environ.get("WG_MPCMDRUN")
    if env:
        return Path(env) if Path(env).is_file() else None
    plat = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft" / "Windows Defender" / "Platform"
    cands = []
    if plat.is_dir():
        cands += sorted((d / "MpCmdRun.exe" for d in plat.iterdir() if d.is_dir()), reverse=True)
    cands.append(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender" / "MpCmdRun.exe")
    return next((c for c in cands if c.is_file()), None)


def parse(output: str) -> list[tuple[str, str]]:
    """(threat name, file path) pairs from MpCmdRun's report."""
    out, threat = [], None
    for ln in output.splitlines():
        m = _THREAT.match(ln)
        if m:
            threat = m.group(1)
            continue
        m = _FILE.match(ln)
        if m and threat:
            out.append((threat, m.group(1).split("->", 1)[0]))
    if threat and not out:
        out.append((threat, ""))
    return out


class Defender:
    def __init__(self, exe: Path):
        self.exe = exe

    def start(self, path: Path) -> subprocess.Popen:
        return subprocess.Popen([str(self.exe), "-Scan", "-ScanType", "3", "-File", str(path), "-DisableRemediation"],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))

    @staticmethod
    def result(proc: subprocess.Popen, timeout: float = 180) -> tuple[str, list[tuple[str, str]], str]:
        """('clean' | 'detected' | 'error', threats, message)."""
        try:
            out, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            return "error", [], f"no answer in {timeout:.0f}s"
        text = out.decode("utf-8", "replace") if out else ""
        if proc.returncode == 0:
            return "clean", [], ""
        if proc.returncode == 2:
            return "detected", parse(text), ""
        last = [ln for ln in text.splitlines() if ln.strip()][-1:] or [f"exit code {proc.returncode}"]
        return "error", [], last[0][:200]
