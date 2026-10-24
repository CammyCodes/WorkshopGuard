"""Findings and verdicts."""

from __future__ import annotations

from dataclasses import dataclass, asdict, field

SEVERITY_WEIGHT = {"info": 0, "low": 1, "medium": 3, "high": 8, "critical": 50}
SEVERITIES = list(SEVERITY_WEIGHT)

CLEAN, SUSPICIOUS, MALICIOUS = "clean", "suspicious", "malicious"


@dataclass
class Finding:
    scanner: str          # clamav | yara | dotnet | pe | files | virustotal | steam
    severity: str         # info | low | medium | high | critical
    rule: str             # short id, e.g. dotnet.process_start
    description: str      # one line a non-expert can read
    file: str = ""        # path inside the item ("a.zip!b.dll" for archive members)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    verdict: str
    score: int
    findings: list[Finding]
    files_scanned: int
    bytes_scanned: int
    sha256: dict[str, str]  # path -> sha256 of every file

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def verdict_for(findings: list[Finding]) -> tuple[str, int]:
    """Any critical finding = malicious. Any high finding, or one file with 3+ different medium findings = suspicious.
    Low/info findings never change the verdict: big framework mods (Harmony, MonoMod) have lots of them."""
    score = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    sev = {f.severity for f in findings}
    if "critical" in sev:
        return MALICIOUS, score
    mediums: dict[str, set[str]] = {}
    for f in findings:
        if f.severity == "medium":
            mediums.setdefault(f.file, set()).add(f.rule)
    if "high" in sev or any(len(rules) >= 3 for rules in mediums.values()):
        return SUSPICIOUS, score
    return CLEAN, score
