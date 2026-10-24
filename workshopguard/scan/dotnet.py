""".NET assembly analysis (Unity/C# mods: PlateUp, RimWorld, Cities: Skylines, ...).

Reads the assembly's metadata without loading or running it: which framework methods it calls (MemberRef),
which native functions it imports (P/Invoke), its string literals (#US heap) and embedded resources. Single
capabilities are mostly "medium" because legit mods use some of them; the combinations that real Workshop malware
needs (download + run, read Steam/Discord secrets + network, republish to the Workshop) are what raise the alarm.
"""

from __future__ import annotations

import logging
import re

import dnfile

logging.getLogger("dnfile").setLevel(logging.ERROR)  # chatty about odd-but-harmless string heaps

from .model import Finding

log = logging.getLogger(__name__)

# (regex on "Namespace.Type::Method", capability, severity, description)
CALLS: list[tuple[str, str, str, str]] = [
    (r"^System\.Diagnostics\.Process::(Start|\.ctor)$|^System\.Diagnostics\.ProcessStartInfo::",
     "exec", "medium", "Can start programs or open web pages (Process.Start)"),
    (r"^System\.Net\.WebClient::(Download|Upload|Open)|^System\.Net\.Http\.HttpClient::|^System\.Net\.WebRequest::Create"
     r"|^System\.Net\.HttpWebRequest::|^UnityEngine\.Networking\.UnityWebRequest::(Get|Post|Put|SendWebRequest)"
     r"|^UnityEngine\.WWW::\.ctor",
     "network", "medium", "Talks to the internet"),
    (r"^System\.Net\.Sockets\.(TcpClient|Socket|UdpClient)::", "sockets", "medium", "Opens raw network sockets"),
    (r"^System\.Reflection\.Assembly::(Load|LoadFile|LoadFrom|UnsafeLoadFrom)$|^System\.AppDomain::(Load|ExecuteAssembly)",
     "loads_code", "low", "Loads other assemblies by name or path"),
    (r"^Microsoft\.CSharp\.CSharpCodeProvider::|^System\.CodeDom\.Compiler\.CodeDomProvider::CompileAssembly",
     "compiles_code", "high", "Compiles and runs new C# code at runtime"),
    (r"^Microsoft\.Win32\.Registry(Key)?::", "registry", "medium", "Reads or writes the Windows registry"),
    (r"^System\.Security\.Cryptography\.ProtectedData::Unprotect$",
     "dpapi", "critical", "Decrypts Windows-protected secrets (how browser password stealers work)"),
    (r"^System\.IO\.Directory::Delete$", "deletes_dirs", "low", "Deletes whole folders"),
    (r"^System\.IO\.File::(WriteAllBytes|Create|OpenWrite)$|^System\.Net\.WebClient::DownloadFile",
     "writes_files", "info", "Writes files"),
    (r"^System\.IO\.Path::(GetTempPath|GetTempFileName)$", "temp_path", "info", "Uses the temp folder"),
    (r"^System\.IO\.File::(Delete|Encrypt)$", "deletes_files", "low", "Deletes files"),
    (r"^System\.Environment::GetFolderPath$|^System\.Environment::ExpandEnvironmentVariables$",
     "user_folders", "low", "Looks up user folders (AppData, Documents, ...)"),
    (r"^System\.IO\.(Directory::(GetFiles|EnumerateFiles|GetDirectories)|DirectoryInfo::(GetFiles|EnumerateFiles))$",
     "enumerates_files", "low", "Lists files in folders"),
    (r"^System\.Convert::FromBase64String$", "base64", "info", "Decodes base64 data"),
    (r"^System\.Security\.Cryptography\.(Aes|Rijndael|RijndaelManaged|AesManaged|AesCryptoServiceProvider|TripleDES)::"
     r"|::CreateDecryptor$", "decrypts", "low", "Decrypts data at runtime"),
    (r"^System\.Reflection\.Emit\.", "emit", "info", "Generates IL at runtime (normal for Harmony patching)"),
    (r"^System\.Windows\.Forms\.Clipboard::|^UnityEngine\.GUIUtility::(get_)?systemCopyBuffer",
     "clipboard", "low", "Reads or writes the clipboard"),
    (r"^System\.Runtime\.InteropServices\.Marshal::(GetDelegateForFunctionPointer|Copy|AllocHGlobal)$",
     "native_mem", "low", "Works with raw native memory"),
    (r"^System\.Threading\.Thread::Sleep$|^System\.Threading\.Tasks\.Task::Delay$", "sleeps", "info", "Waits/sleeps"),
    # Steam: what self-spreading Workshop malware does with the victim's own account
    (r"^Steamworks\.SteamUGC::(CreateItem|SubmitItemUpdate|SetItemContent|StartItemUpdate)$"
     r"|^Steamworks\.Ugc\.Editor::(NewCommunityFile|SubmitAsync|WithContent|\.ctor)$",
     "workshop_publish", "high", "Uploads/updates Workshop items from inside the game (how 2026 worms spread)"),
    (r"^Steamworks\.SteamFriends::(ReplyToFriendMessage|SendClanChatMessage|InviteUserToGame)$"
     r"|^Steamworks\.Friend::(SendMessage|InviteToGame)$",
     "friend_messages", "high", "Sends messages to the player's Steam friends"),
    (r"^Steamworks\.SteamUser::(GetAuthSessionTicket|GetAuthTicketForWebApi|GetEncryptedAppTicket)$"
     r"|^Steamworks\.SteamUser::(GetAuthSessionTicketAsync|GetAuthTicketForWebApiAsync)$",
     "steam_ticket", "medium", "Gets a Steam login/auth ticket for the player"),
]
CALLS_RE = [(re.compile(p), cap, sev, desc) for p, cap, sev, desc in CALLS]

# P/Invoke imports: (dll regex, function regex, capability, severity, description)
PINVOKE: list[tuple[str, str, str, str, str]] = [
    (r"kernel32", r"^(VirtualAllocEx|VirtualProtectEx|WriteProcessMemory|CreateRemoteThread(Ex)?|"
                  r"NtUnmapViewOfSection|QueueUserAPC|OpenProcess)$",
     "injection", "high", "Touches other processes' memory (process injection)"),
    (r"kernel32", r"^(VirtualAlloc|VirtualProtect)$", "native_mem", "low",
     "Allocates executable memory in its own process (normal for Harmony/MonoMod patching)"),
    (r"kernel32", r"^(LoadLibrary\w*|GetProcAddress)$", "native_loader", "low", "Loads native code by name"),
    (r"kernel32", r"^(WinExec|CreateProcess\w*)$", "exec", "high", "Starts other programs (native)"),
    (r"urlmon", r"^URLDownloadToFile\w*$", "download_exec", "critical", "Downloads a file straight to disk (dropper API)"),
    (r"shell32", r"^ShellExecute\w*$", "exec", "high", "Starts other programs (ShellExecute)"),
    (r"user32", r"^(SetWindowsHookEx\w*|GetAsyncKeyState|GetKeyboardState|RegisterRawInputDevices)$",
     "keylogger", "high", "Watches keystrokes system-wide"),
    (r"crypt32", r"^CryptUnprotectData$", "dpapi", "critical", "Decrypts Windows-protected secrets (stealer API)"),
    (r"advapi32", r"^(RegSetValue\w*|RegCreateKey\w*|CreateService\w*|OpenSCManager\w*)$",
     "persistence", "high", "Writes registry/services (persistence)"),
    (r"ntdll", r"^(NtSetInformationProcess|RtlSetProcessIsCritical|NtRaiseHardError)$",
     "sabotage", "critical", "Crashes/BSODs the machine or makes itself unkillable"),
    (r"wininet|winhttp", r".*", "network", "medium", "Native internet API"),
]
PINVOKE_RE = [(re.compile(d, re.I), re.compile(f, re.I), cap, sev, desc) for d, f, cap, sev, desc in PINVOKE]

# String literals that only make sense for a stealer/dropper. (YARA also checks these across all file types.)
STRINGS: list[tuple[str, str, str, str]] = [
    (r"(?i)discord(app)?\.com/api/webhooks/", "exfil_discord", "high", "Contains a Discord webhook (common exfiltration)"),
    (r"(?i)api\.telegram\.org/bot", "exfil_telegram", "high", "Contains a Telegram bot API URL (common exfiltration)"),
    (r"(?i)\bssfn|loginusers\.vdf|config[\/]+config\.vdf|\blocal\.vdf", "steam_secrets", "high",
     "References Steam login/session files"),
    (r"(?i)Local Storage[\/]+leveldb|\bdiscord(canary|ptb)\b", "discord_token", "high",
     "References Discord's token storage"),
    (r"Login Data|Local State|User Data[\/]+Default|Network[\/]+Cookies|logins\.json|key4\.db|cookies\.sqlite",
     "browser_secrets", "high", "References browser password/cookie stores"),
    (r"(?i)wallet\.dat|exodus\.wallet|Electrum[\/]+wallets|nkbihfbeogaeaoehlefnkodbefgpgknn",
     "crypto_wallets", "high", "References crypto wallets"),
    (r"(?i)\b(powershell(\.exe)?|cmd\.exe|mshta(\.exe)?|rundll32|regsvr32|certutil|bitsadmin|schtasks|wscript|cscript)\b",
     "lolbin", "high", "Mentions Windows tools malware uses to run payloads"),
    (r"(?i)\s-enc(odedcommand)?\s|-w(indowstyle)?\s+hidden|DownloadString\(|\bIEX\s*\(|Invoke-Expression",
     "powershell_payload", "critical", "Contains a PowerShell download/exec one-liner"),
    (r"(?i)https?://(?!127\.|0\.0\.0\.0|192\.168\.|10\.)(\d{1,3}\.){3}\d{1,3}", "ip_url", "medium",
     "Contains a URL with a raw public IP address"),
    (r"(?i)pastebin\.com/raw|paste\.ee/r|hastebin|transfer\.sh|anonfiles|gofile\.io|cdn\.discordapp\.com/attachments"
     r"|ngrok|trycloudflare\.com|\.onion\b",
     "payload_host", "medium", "Points at a host often used to serve payloads"),
    (r"(?i)CurrentVersion[\/]+Run(Once)?\b", "autorun", "high", "References the Windows startup (Run) key"),
    (r"(?i)Start Menu[\/]+Programs[\/]+Startup", "startup_folder", "high", "References the Startup folder"),
    (r"(?i)vssadmin|delete shadows|bcdedit|wbadmin", "anti_recovery", "critical", "Deletes Windows backups/recovery"),
    (r"(?i)\.(exe|bat|cmd|ps1|vbs|scr|msi|hta)\b", "exe_strings", "low", "Mentions program/script file names"),
]
STRINGS_RE = [(re.compile(p), cap, sev, desc) for p, cap, sev, desc in STRINGS]

OBFUSCATOR_MARKERS = {
    "ConfusedByAttribute": "ConfuserEx", "DotfuscatorAttribute": "Dotfuscator", "SmartAssembly": "SmartAssembly",
    "BabelObfuscatorAttribute": "Babel", "ObfuscatedByGoliath": "Goliath", "Xenocode": "Xenocode",
    "NETGuard": ".NET Guard", "EazfuscatorAttribute": "Eazfuscator", "Agile.NET": "Agile.NET",
}

# Combinations real malware needs. (required capabilities, any-of capabilities, rule, severity, description)
COMBOS: list[tuple[set[str], set[str], str, str, str]] = [
    ({"network", "loads_code_bytes"}, set(), "loader", "critical",
     "Downloads data and loads it as code (remote payload loader)"),
    ({"network", "compiles_code"}, set(), "remote_compile", "critical",
     "Downloads data and compiles it as code (remote payload loader)"),
    # Process.Start + internet alone is usually "open a web page"; a dropper also needs something to launch.
    ({"network", "exec"}, {"exe_strings", "temp_path", "lolbin"}, "dropper", "critical",
     "Downloads something and starts a program (dropper pattern)"),
    (set(), {"steam_secrets", "discord_token", "browser_secrets", "crypto_wallets", "dpapi"}, "stealer_targets", "high",
     "Looks for account secrets"),
    ({"network"}, {"steam_secrets", "discord_token", "browser_secrets", "crypto_wallets", "dpapi"}, "stealer", "critical",
     "Reads account secrets and can send them over the internet (stealer pattern)"),
    (set(), {"exfil_discord", "exfil_telegram"}, "exfil_with_secrets_or_files", "critical", ""),  # refined below
    ({"workshop_publish"}, {"user_folders", "enumerates_files", "network", "friend_messages"}, "worm", "critical",
     "Can republish Workshop items and touch other files/accounts (self-spreading pattern)"),
    ({"base64", "loads_code_bytes"}, set(), "packed_loader", "high", "Decodes hidden data and loads it as code"),
    ({"base64", "writes_files", "exec"}, {"exe_strings", "temp_path", "lolbin"}, "embedded_dropper", "high",
     "Decodes hidden data, writes it to disk and can start programs"),
    ({"deletes_dirs", "enumerates_files", "user_folders"}, set(), "wiper", "high",
     "Walks user folders and deletes directories (file-wiper pattern)"),
    ({"lolbin"}, {"exec"}, "lolbin_exec", "critical", "Runs a Windows system tool (cmd/powershell/...) as a payload"),
]


def _typeref_name(row) -> str:
    try:
        ns = str(row.TypeNamespace or "")
        name = str(row.TypeName or "")
        if not ns:
            scope = getattr(row, "ResolutionScope", None)
            parent = getattr(scope, "row", None)
            if parent is not None and getattr(scope, "table", None) is not None and scope.table.name == "TypeRef":
                return f"{_typeref_name(parent)}+{name}"
        return f"{ns}.{name}" if ns else name
    except Exception:  # noqa: BLE001
        return "?"


def _cu(b: bytes, i: int) -> tuple[int, int]:
    """ECMA-335 compressed unsigned integer -> (value, next index)."""
    x = b[i]
    if x & 0x80 == 0:
        return x, i + 1
    if x & 0xC0 == 0x80:
        return ((x & 0x3F) << 8) | b[i + 1], i + 2
    return ((x & 0x1F) << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3], i + 4


def _skip_type(b: bytes, i: int) -> int:
    t = b[i]
    i += 1
    if t in (0x11, 0x12, 0x13, 0x1E):  # valuetype/class token, generic var/mvar
        return _cu(b, i)[1]
    if t in (0x0F, 0x10, 0x1D, 0x45):  # pointer, byref, szarray, pinned
        return _skip_type(b, i)
    if t == 0x15:  # generic instance: kind, type token, arg count, args
        i = _cu(b, i + 1)[1]
        n, i = _cu(b, i)
        for _ in range(n):
            i = _skip_type(b, i)
    return i


def _takes_byte_array(sig: bytes) -> bool:
    """True if a method signature has a byte[] parameter: Assembly.Load(byte[]) rather than Load(string)."""
    try:
        i = 1
        if sig[0] & 0x10:  # generic method
            i = _cu(sig, i)[1]
        n, i = _cu(sig, i)
        i = _skip_type(sig, i)  # return type
        for _ in range(n):
            if sig[i] == 0x1D and sig[i + 1] == 0x05:
                return True
            i = _skip_type(sig, i)
    except IndexError:
        pass
    return False


def _member_refs(net) -> list[tuple[str, bytes]]:
    out = []
    table = getattr(net.mdtables, "MemberRef", None)
    for mr in table or []:
        try:
            cls = mr.Class
            sig = bytes(getattr(mr.Signature, "value", None) or b"")
            if cls.table is not None and cls.table.name == "TypeRef":
                out.append((f"{_typeref_name(cls.row)}::{mr.Name}", sig))
            else:
                out.append((f"?::{mr.Name}", sig))
        except Exception:  # noqa: BLE001
            continue
    return out


def _pinvokes(net) -> list[tuple[str, str]]:
    out = []
    for im in getattr(net.mdtables, "ImplMap", None) or []:
        try:
            out.append((str(im.ImportScope.row.Name), str(im.ImportName)))
        except Exception:  # noqa: BLE001
            continue
    return out


def _user_strings(net) -> list[str]:
    heap = getattr(net, "user_strings", None)
    if heap is None:
        return []
    out, off = [], 1
    size = heap.sizeof()
    while off < size:
        try:
            res = heap.get_with_size(off)
        except Exception:  # noqa: BLE001
            break
        if not res:
            break
        data, n = res
        if n <= 0:
            break
        if data:
            try:
                out.append(bytes(data[:-1] if len(data) % 2 else data).decode("utf-16-le", "replace"))
            except Exception:  # noqa: BLE001
                pass
        off += n
    return out


def analyze(data: bytes, path: str) -> tuple[list[Finding], dict]:
    """Return findings and a small summary (references, P/Invokes) for the dashboard."""
    try:
        pe = dnfile.dnPE(data=data, fast_load=False)
    except Exception as e:  # noqa: BLE001
        return [Finding("dotnet", "low", "dotnet.unparseable", f"Could not parse .NET metadata ({e})", path)], {}
    net = pe.net
    if net is None or net.mdtables is None:
        return [], {}

    findings: list[Finding] = []
    by_cap: dict[str, Finding | None] = {}

    def add(cap: str, sev: str, desc: str, ev: str, rule_prefix: str = "dotnet"):
        if cap not in by_cap:
            f = Finding("dotnet", sev, f"{rule_prefix}.{cap}", desc, path, []) if sev != "info" else None
            by_cap[cap] = f
            if f:
                findings.append(f)
        f = by_cap[cap]
        if f is not None and len(f.evidence) < 6 and ev not in f.evidence:
            f.evidence.append(ev)

    refs = _member_refs(net)
    for ref, sig in refs:
        for rx, cap, sev, desc in CALLS_RE:
            if rx.search(ref):
                if cap == "loads_code" and _takes_byte_array(sig):
                    add("loads_code_bytes", "medium", "Loads code straight from memory (Assembly.Load(byte[]))", ref)
                else:
                    add(cap, sev, desc, ref)

    pinv = _pinvokes(net)
    for dll, fn in pinv:
        for drx, frx, cap, sev, desc in PINVOKE_RE:
            if drx.search(dll) and frx.search(fn):
                add(cap, sev, desc, f"{dll}!{fn}", "dotnet.pinvoke")

    strings = _user_strings(net)
    for s in strings:
        for rx, cap, sev, desc in STRINGS_RE:
            if rx.search(s):
                add(cap, sev, desc, s[:160], "dotnet.string")

    # obfuscators: marker types/attributes defined in the assembly
    names = set()
    for tbl in ("TypeDef", "TypeRef"):
        for row in getattr(net.mdtables, tbl, None) or []:
            try:
                names.add(str(row.TypeName))
            except Exception:  # noqa: BLE001
                pass
    for marker, product in OBFUSCATOR_MARKERS.items():
        if any(marker in n for n in names):
            add("obfuscated", "high", f"Obfuscated with {product}: the code is deliberately hidden from review", marker)
            break
    else:
        weird = [n for n in names if n and not n.isascii()]
        if len(weird) >= 10:
            findings.append(Finding("dotnet", "medium", "dotnet.obfuscated_names",
                                    "Many type names are unreadable symbols (typical of obfuscation)", path, weird[:5]))

    # embedded executables in resources
    for res in getattr(net, "resources", None) or []:
        blob = getattr(res, "data", None)
        if isinstance(blob, (bytes, bytearray)) and blob[:2] == b"MZ":
            add("embedded_pe", "medium", "Carries another program inside its resources", str(res.name))

    # combinations
    have = set(by_cap)
    for need, anyof, rule, sev, desc in COMBOS:
        if not need <= have or (anyof and not (anyof & have)):
            continue
        if rule == "exfil_with_secrets_or_files":
            if have & {"steam_secrets", "discord_token", "browser_secrets", "crypto_wallets", "enumerates_files"}:
                findings.append(Finding("dotnet", "critical", "dotnet.combo.exfil",
                                        "Has a hard-coded chat webhook/bot and reads secrets or files (exfiltration)",
                                        path, sorted(have & {"exfil_discord", "exfil_telegram"})))
            continue
        findings.append(Finding("dotnet", sev, f"dotnet.combo.{rule}", desc, path,
                                sorted((need | anyof) & have)))

    summary = {"capabilities": sorted(have), "pinvoke": [f"{d}!{f}" for d, f in pinv][:50],
               "member_refs": len(refs), "strings": len(strings)}
    return findings, summary
