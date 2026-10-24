"""Optional VirusTotal hash lookup for executables. Only the SHA-256 is sent, never the file."""

from __future__ import annotations

import logging
import time

import requests

from .model import Finding

log = logging.getLogger(__name__)


class VirusTotal:
    def __init__(self, api_key: str, per_minute: int = 4):
        self.key = api_key
        self.gap = 60.0 / per_minute  # free API: 4 lookups a minute
        self._last = 0.0
        self.cache: dict[str, Finding | None] = {}

    def lookup(self, sha256: str, path: str) -> Finding | None:
        if sha256 in self.cache:
            return self.cache[sha256]
        wait = self._last + self.gap - time.time()
        if wait > 0:
            time.sleep(wait)
        self._last = time.time()
        try:
            r = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}",
                             headers={"x-apikey": self.key}, timeout=30)
        except requests.RequestException as e:
            log.warning("VirusTotal lookup failed: %s", e)
            return None
        if r.status_code == 404:
            self.cache[sha256] = None  # never seen: new file, normal for a fresh mod
            return None
        if r.status_code != 200:
            log.warning("VirusTotal HTTP %s", r.status_code)
            return None
        stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})
        bad, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        f = None
        link = f"https://www.virustotal.com/gui/file/{sha256}"
        if bad >= 3:
            f = Finding("virustotal", "critical", "virustotal.malicious", f"{bad} antivirus engines flag this file", path,
                        [link])
        elif bad or sus:
            f = Finding("virustotal", "medium", "virustotal.some_flags",
                        f"{bad} engines say malicious, {sus} suspicious", path, [link])
        self.cache[sha256] = f
        return f
