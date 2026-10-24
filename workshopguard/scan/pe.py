"""Native Windows executables/DLLs: imports, packers, and whether it's really .NET."""

from __future__ import annotations

import math
import re

import pefile

from .model import Finding

IMPORTS: list[tuple[str, str, str, str]] = [
    (r"^(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread(Ex)?|NtUnmapViewOfSection|QueueUserAPC|"
     r"SetThreadContext)$", "high", "pe.injection", "Process-injection APIs"),
    (r"^URLDownloadToFile\w*$", "critical", "pe.downloader", "Downloads files straight to disk"),
    (r"^(InternetOpenUrl\w*|InternetReadFile|WinHttpOpen|WinHttpSendRequest|HttpSendRequest\w*)$", "medium",
     "pe.network", "Internet APIs"),
    (r"^(WinExec|ShellExecute\w*|CreateProcess\w*)$", "medium", "pe.exec", "Starts other programs"),
    (r"^(SetWindowsHookEx\w*|GetAsyncKeyState)$", "high", "pe.keylogger", "Watches keystrokes"),
    (r"^CryptUnprotectData$", "high", "pe.dpapi", "Decrypts Windows-protected secrets (browser stealers)"),
    (r"^(RegSetValueEx\w*|CreateService\w*)$", "medium", "pe.persistence", "Writes registry values / services"),
    (r"^(IsDebuggerPresent|CheckRemoteDebuggerPresent)$", "low", "pe.antidebug", "Checks for a debugger"),
]
IMPORTS_RE = [(re.compile(p, re.I), s, r, d) for p, s, r, d in IMPORTS]
PACKER_SECTIONS = {"UPX0": "UPX", "UPX1": "UPX", ".aspack": "ASPack", ".themida": "Themida", ".vmp0": "VMProtect",
                   ".vmp1": "VMProtect", ".enigma1": "Enigma", ".petite": "Petite", "MPRESS1": "MPRESS"}


def is_pe(data: bytes) -> bool:
    if data[:2] != b"MZ" or len(data) < 0x40:
        return False
    off = int.from_bytes(data[0x3C:0x40], "little")
    return data[off:off + 4] == b"PE\0\0"


def is_dotnet(pe: pefile.PE) -> bool:
    try:
        d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]]
        return d.VirtualAddress != 0 and d.Size != 0
    except (IndexError, AttributeError):
        return False


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def analyze(data: bytes, path: str) -> tuple[list[Finding], dict]:
    """Returns (findings, info). info['dotnet'] says whether to hand it to the .NET analyzer too."""
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
        ])
    except pefile.PEFormatError as e:
        return [Finding("pe", "medium", "pe.malformed", f"Broken Windows executable header ({e})", path)], {}

    info = {"dotnet": is_dotnet(pe), "dll": pe.is_dll(), "machine": hex(pe.FILE_HEADER.Machine),
            "signed": pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size > 0}
    findings: list[Finding] = []
    if info["dotnet"]:
        return findings, info  # managed code: imports are just mscoree, the .NET analyzer does the real work

    hits: dict[str, Finding] = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("ascii", "replace") if entry.dll else "?"
        for imp in entry.imports:
            if not imp.name:
                continue
            name = imp.name.decode("ascii", "replace")
            for rx, sev, rule, desc in IMPORTS_RE:
                if rx.search(name):
                    f = hits.setdefault(rule, Finding("pe", sev, rule, desc, path, []))
                    if len(f.evidence) < 6:
                        f.evidence.append(f"{dll}!{name}")
    findings += hits.values()
    if {"pe.downloader", "pe.network"} & set(hits) and "pe.exec" in hits:
        findings.append(Finding("pe", "critical", "pe.combo.dropper",
                                "Downloads files and starts programs (dropper pattern)", path))

    for s in pe.sections:
        name = s.Name.rstrip(b"\0").decode("ascii", "replace")
        if name in PACKER_SECTIONS:
            findings.append(Finding("pe", "high", "pe.packed",
                                    f"Packed with {PACKER_SECTIONS[name]}: real code is hidden until it runs", path,
                                    [name]))
            break
    else:
        hi = [s for s in pe.sections if s.SizeOfRawData > 4096 and _entropy(s.get_data()[:262144]) > 7.4
              and s.Characteristics & 0x20000000]  # executable + near-random = packed/encrypted code
        if hi:
            findings.append(Finding("pe", "medium", "pe.high_entropy_code",
                                    "Executable code section looks encrypted/compressed", path,
                                    [s.Name.rstrip(b"\0").decode("ascii", "replace") for s in hi]))
    return findings, info
