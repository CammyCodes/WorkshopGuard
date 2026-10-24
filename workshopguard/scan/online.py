"""Online multi-engine lookups. By default only a file's SHA-256 is sent. With upload on (deep-scan --upload),
files those services have never seen are uploaded for a full scan. Workshop files are public anyway, but uploads
are shared with the services' partners, so it's opt-in.

  VirusTotal     ~70 antivirus engines                  free key: virustotal.com
  MetaDefender   ~20 antivirus engines (OPSWAT)         free key: metadefender.opswat.com
  MalwareBazaar  abuse.ch's database of known malware   free key: auth.abuse.ch
"""

from __future__ import annotations

import logging
import time

import requests

from .model import Finding

log = logging.getLogger(__name__)


class _Throttle:
    def __init__(self, per_minute: float):
        self.gap, self.last = 60.0 / per_minute, 0.0

    def wait(self):
        d = self.last + self.gap - time.time()
        if d > 0:
            time.sleep(d)
        self.last = time.time()


class OnlineEngine:
    name = ""
    label = ""

    def __init__(self, api_key: str, upload: bool = False):
        self.key, self.upload = api_key, upload
        self.session = requests.Session()

    def check(self, sha256: str, data: bytes, filename: str, rel: str) -> tuple[str, Finding | None]:
        """Returns (status, finding). status: detected | clean | unknown | error"""
        raise NotImplementedError


def _verdict(engine: str, label: str, bad: int, total: int, rel: str, link: str) -> Finding | None:
    if bad >= 3:
        return Finding(engine, "critical", f"{engine}.malicious", f"{label}: {bad}/{total} antivirus engines flag "
                       "this file", rel, [link])
    if bad:
        return Finding(engine, "medium", f"{engine}.some_flags", f"{label}: {bad}/{total} engines flag this file "
                       "(often false alarms at this level)", rel, [link])
    return None


class VirusTotal(OnlineEngine):
    name, label = "virustotal", "VirusTotal"
    API = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, upload: bool = False, per_minute: float = 4):
        super().__init__(api_key, upload)
        self.session.headers["x-apikey"] = api_key
        self.t = _Throttle(per_minute)  # free tier: 4 requests a minute

    def _stats(self, sha256: str):
        self.t.wait()
        r = self.session.get(f"{self.API}/files/{sha256}", timeout=30)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()["data"]["attributes"].get("last_analysis_stats", {})

    def check(self, sha256, data, filename, rel):
        link = f"https://www.virustotal.com/gui/file/{sha256}"
        try:
            stats = self._stats(sha256)
            if stats is None and self.upload and len(data) <= 32 * 1024 * 1024:
                self.t.wait()
                r = self.session.post(f"{self.API}/files", files={"file": (filename, data)}, timeout=120)
                r.raise_for_status()
                aid = r.json()["data"]["id"]
                for _ in range(30):  # up to ~10 minutes on the free tier
                    self.t.wait()
                    a = self.session.get(f"{self.API}/analyses/{aid}", timeout=30).json()["data"]["attributes"]
                    if a.get("status") == "completed":
                        stats = a.get("stats", {})
                        break
            if stats is None:
                return "unknown", None
        except (requests.RequestException, KeyError, ValueError) as e:
            log.warning("VirusTotal: %s", e)
            return "error", None
        bad = int(stats.get("malicious", 0))
        total = sum(int(v) for k, v in stats.items() if k in ("malicious", "suspicious", "undetected", "harmless"))
        f = _verdict(self.name, self.label, bad, total, rel, link)
        return ("detected" if f else "clean"), f


class MetaDefender(OnlineEngine):
    name, label = "metadefender", "MetaDefender"
    API = "https://api.metadefender.com/v4"

    def __init__(self, api_key: str, upload: bool = False):
        super().__init__(api_key, upload)
        self.session.headers["apikey"] = api_key
        self.t = _Throttle(10)

    def _result(self, sha256: str):
        self.t.wait()
        r = self.session.get(f"{self.API}/hash/{sha256}", timeout=30)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json().get("scan_results")

    def check(self, sha256, data, filename, rel):
        link = f"https://metadefender.com/results/hash/{sha256}"
        try:
            res = self._result(sha256)
            if res is None and self.upload and len(data) <= 140 * 1024 * 1024:
                self.t.wait()
                r = self.session.post(f"{self.API}/file", data=data, timeout=120,
                                      headers={"filename": filename, "Content-Type": "application/octet-stream"})
                r.raise_for_status()
                did = r.json()["data_id"]
                for _ in range(40):
                    self.t.wait()
                    j = self.session.get(f"{self.API}/file/{did}", timeout=30).json()
                    if j.get("scan_results", {}).get("progress_percentage", 0) >= 100:
                        res = j["scan_results"]
                        break
            if not res:
                return "unknown", None
        except (requests.RequestException, KeyError, ValueError) as e:
            log.warning("MetaDefender: %s", e)
            return "error", None
        f = _verdict(self.name, self.label, int(res.get("total_detected_avs", 0)), int(res.get("total_avs", 0)), rel,
                     link)
        return ("detected" if f else "clean"), f


class MalwareBazaar(OnlineEngine):
    """Only knows malware: a hit is a confirmed sample, a miss means nothing either way."""
    name, label = "malwarebazaar", "MalwareBazaar"
    API = "https://mb-api.abuse.ch/api/v1/"

    def __init__(self, api_key: str, upload: bool = False):
        super().__init__(api_key, False)  # uploads to MalwareBazaar are for confirmed malware only
        self.session.headers["Auth-Key"] = api_key

    def check(self, sha256, data, filename, rel):
        try:
            r = self.session.post(self.API, data={"query": "get_info", "hash": sha256}, timeout=30)
            r.raise_for_status()
            j = r.json()
        except (requests.RequestException, ValueError) as e:
            log.warning("MalwareBazaar: %s", e)
            return "error", None
        if j.get("query_status") != "ok":
            return ("unknown" if j.get("query_status") in ("hash_not_found", "no_results") else "error"), None
        d = (j.get("data") or [{}])[0]
        fam = d.get("signature") or ", ".join(d.get("tags") or []) or "unnamed family"
        return "detected", Finding(self.name, "critical", "malwarebazaar.known_malware",
                                   f"MalwareBazaar: known malware ({fam})", rel,
                                   [f"https://bazaar.abuse.ch/sample/{sha256}/"])
