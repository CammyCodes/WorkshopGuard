// WorkshopGuard ModGuard: check mods before a Unity/C# game loads them. MIT licence, github.com/CammyCodes/WorkshopGuard
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace WorkshopGuard
{
    /// <summary>What a mod's code can do, read from its metadata: which framework methods it calls, which native
    /// functions it imports, its string literals and resources. Single capabilities are mostly "medium" because normal
    /// mods use some of them; the combinations real Workshop malware needs (download + run, read Steam/Discord/browser
    /// secrets + send, republish to the Workshop) are what raise the alarm. A port of WorkshopGuard's dotnet.py, rule
    /// for rule, so the in-game check and the server agree.</summary>
    public static class DotNetAnalyzer
    {
        const RegexOptions Opt = RegexOptions.CultureInvariant;

        sealed class Rule
        {
            public Regex Rx, Dll;
            public string Cap, Desc;
            public Severity Sev;
            public Rule(string rx, string cap, Severity sev, string desc, string dll = null)
            {
                Rx = new Regex(rx, Opt);
                Dll = dll == null ? null : new Regex(dll, Opt | RegexOptions.IgnoreCase);
                Cap = cap; Sev = sev; Desc = desc;
            }
        }

        static readonly Rule[] Calls =
        {
            new Rule(@"^System\.Diagnostics\.Process::(Start|\.ctor)$|^System\.Diagnostics\.ProcessStartInfo::",
                     "exec", Severity.Medium, "Can start programs or open web pages (Process.Start)"),
            new Rule(@"^System\.Net\.WebClient::(Download|Upload|Open)|^System\.Net\.Http\.HttpClient::|^System\.Net\.WebRequest::Create" +
                     @"|^System\.Net\.HttpWebRequest::|^UnityEngine\.Networking\.UnityWebRequest::(Get|Post|Put|SendWebRequest)" +
                     @"|^UnityEngine\.WWW::\.ctor", "network", Severity.Medium, "Talks to the internet"),
            new Rule(@"^System\.Net\.Sockets\.(TcpClient|Socket|UdpClient)::", "sockets", Severity.Medium, "Opens raw network sockets"),
            new Rule(@"^System\.Reflection\.Assembly::(Load|LoadFile|LoadFrom|UnsafeLoadFrom)$|^System\.AppDomain::(Load|ExecuteAssembly)",
                     "loads_code", Severity.Low, "Loads other assemblies by name or path"),
            new Rule(@"^Microsoft\.CSharp\.CSharpCodeProvider::|^System\.CodeDom\.Compiler\.CodeDomProvider::CompileAssembly",
                     "compiles_code", Severity.High, "Compiles and runs new C# code at runtime"),
            new Rule(@"^Microsoft\.Win32\.Registry(Key)?::", "registry", Severity.Medium, "Reads or writes the Windows registry"),
            new Rule(@"^System\.Security\.Cryptography\.ProtectedData::Unprotect$", "dpapi", Severity.Critical,
                     "Decrypts Windows-protected secrets (how browser password stealers work)"),
            new Rule(@"^System\.IO\.Directory::Delete$", "deletes_dirs", Severity.Low, "Deletes whole folders"),
            new Rule(@"^System\.IO\.File::(WriteAllBytes|Create|OpenWrite)$|^System\.Net\.WebClient::DownloadFile",
                     "writes_files", Severity.Info, "Writes files"),
            new Rule(@"^System\.IO\.Path::(GetTempPath|GetTempFileName)$", "temp_path", Severity.Info, "Uses the temp folder"),
            new Rule(@"^System\.IO\.File::(Delete|Encrypt)$", "deletes_files", Severity.Low, "Deletes files"),
            new Rule(@"^System\.Environment::GetFolderPath$|^System\.Environment::ExpandEnvironmentVariables$",
                     "user_folders", Severity.Low, "Looks up user folders (AppData, Documents, ...)"),
            new Rule(@"^System\.IO\.(Directory::(GetFiles|EnumerateFiles|GetDirectories)|DirectoryInfo::(GetFiles|EnumerateFiles))$",
                     "enumerates_files", Severity.Low, "Lists files in folders"),
            new Rule(@"^System\.Convert::FromBase64String$", "base64", Severity.Info, "Decodes base64 data"),
            new Rule(@"^System\.Security\.Cryptography\.(Aes|Rijndael|RijndaelManaged|AesManaged|AesCryptoServiceProvider|TripleDES)::" +
                     @"|::CreateDecryptor$", "decrypts", Severity.Low, "Decrypts data at runtime"),
            new Rule(@"^System\.Reflection\.Emit\.", "emit", Severity.Info, "Generates IL at runtime (normal for Harmony patching)"),
            new Rule(@"^System\.Windows\.Forms\.Clipboard::|^UnityEngine\.GUIUtility::(get_)?systemCopyBuffer",
                     "clipboard", Severity.Low, "Reads or writes the clipboard"),
            new Rule(@"^System\.Runtime\.InteropServices\.Marshal::(GetDelegateForFunctionPointer|Copy|AllocHGlobal)$",
                     "native_mem", Severity.Low, "Works with raw native memory"),
            new Rule(@"^System\.Threading\.Thread::Sleep$|^System\.Threading\.Tasks\.Task::Delay$", "sleeps", Severity.Info, "Waits/sleeps"),
            new Rule(@"^Steamworks\.SteamUGC::(CreateItem|SubmitItemUpdate|SetItemContent|StartItemUpdate)$" +
                     @"|^Steamworks\.Ugc\.Editor::(NewCommunityFile|SubmitAsync|WithContent|\.ctor)$",
                     "workshop_publish", Severity.High, "Uploads/updates Workshop items from inside the game (how 2026 worms spread)"),
            new Rule(@"^Steamworks\.SteamFriends::(ReplyToFriendMessage|SendClanChatMessage|InviteUserToGame)$" +
                     @"|^Steamworks\.Friend::(SendMessage|InviteToGame)$",
                     "friend_messages", Severity.High, "Sends messages to the player's Steam friends"),
            new Rule(@"^Steamworks\.SteamUser::(GetAuthSessionTicket|GetAuthTicketForWebApi|GetEncryptedAppTicket)$" +
                     @"|^Steamworks\.SteamUser::(GetAuthSessionTicketAsync|GetAuthTicketForWebApiAsync)$",
                     "steam_ticket", Severity.Medium, "Gets a Steam login/auth ticket for the player"),
        };

        static readonly Rule[] PInvoke =
        {
            new Rule(@"^(VirtualAllocEx|VirtualProtectEx|WriteProcessMemory|CreateRemoteThread(Ex)?|NtUnmapViewOfSection|QueueUserAPC|OpenProcess)$",
                     "injection", Severity.High, "Touches other processes' memory (process injection)", "kernel32"),
            new Rule(@"^(VirtualAlloc|VirtualProtect)$", "native_mem", Severity.Low,
                     "Allocates executable memory in its own process (normal for Harmony/MonoMod patching)", "kernel32"),
            new Rule(@"^(LoadLibrary\w*|GetProcAddress)$", "native_loader", Severity.Low, "Loads native code by name", "kernel32"),
            new Rule(@"^(WinExec|CreateProcess\w*)$", "exec", Severity.High, "Starts other programs (native)", "kernel32"),
            new Rule(@"^URLDownloadToFile\w*$", "download_exec", Severity.Critical, "Downloads a file straight to disk (dropper API)", "urlmon"),
            new Rule(@"^ShellExecute\w*$", "exec", Severity.High, "Starts other programs (ShellExecute)", "shell32"),
            new Rule(@"^(SetWindowsHookEx\w*|GetAsyncKeyState|GetKeyboardState|RegisterRawInputDevices)$",
                     "keylogger", Severity.High, "Watches keystrokes system-wide", "user32"),
            new Rule(@"^CryptUnprotectData$", "dpapi", Severity.Critical, "Decrypts Windows-protected secrets (stealer API)", "crypt32"),
            new Rule(@"^(RegSetValue\w*|RegCreateKey\w*|CreateService\w*|OpenSCManager\w*)$",
                     "persistence", Severity.High, "Writes registry/services (persistence)", "advapi32"),
            new Rule(@"^(NtSetInformationProcess|RtlSetProcessIsCritical|NtRaiseHardError)$",
                     "sabotage", Severity.Critical, "Crashes/BSODs the machine or makes itself unkillable", "ntdll"),
            new Rule(@".*", "network", Severity.Medium, "Native internet API", "wininet|winhttp"),
        };

        static readonly Rule[] Strings =
        {
            new Rule(@"(?i)discord(app)?\.com/api/webhooks/", "exfil_discord", Severity.High, "Contains a Discord webhook (common exfiltration)"),
            new Rule(@"(?i)api\.telegram\.org/bot", "exfil_telegram", Severity.High, "Contains a Telegram bot API URL (common exfiltration)"),
            new Rule(@"(?i)\bssfn|loginusers\.vdf|config[\\/]+config\.vdf|\blocal\.vdf", "steam_secrets", Severity.High,
                     "References Steam login/session files"),
            new Rule(@"(?i)Local Storage[\\/]+leveldb|\bdiscord(canary|ptb)\b", "discord_token", Severity.High,
                     "References Discord's token storage"),
            new Rule(@"Login Data|Local State|User Data[\\/]+Default|Network[\\/]+Cookies|logins\.json|key4\.db|cookies\.sqlite",
                     "browser_secrets", Severity.High, "References browser password/cookie stores"),
            new Rule(@"(?i)wallet\.dat|exodus\.wallet|Electrum[\\/]+wallets|nkbihfbeogaeaoehlefnkodbefgpgknn",
                     "crypto_wallets", Severity.High, "References crypto wallets"),
            new Rule(@"(?i)\b(powershell(\.exe)?|cmd\.exe|mshta(\.exe)?|rundll32|regsvr32|certutil|bitsadmin|schtasks|wscript|cscript)\b",
                     "lolbin", Severity.High, "Mentions Windows tools malware uses to run payloads"),
            new Rule(@"(?i)\s-enc(odedcommand)?\s|-w(indowstyle)?\s+hidden|DownloadString\(|\bIEX\s*\(|Invoke-Expression",
                     "powershell_payload", Severity.Critical, "Contains a PowerShell download/exec one-liner"),
            new Rule(@"(?i)https?://(?!127\.|0\.0\.0\.0|192\.168\.|10\.)(\d{1,3}\.){3}\d{1,3}", "ip_url", Severity.Medium,
                     "Contains a URL with a raw public IP address"),
            new Rule(@"(?i)pastebin\.com/raw|paste\.ee/r|hastebin|transfer\.sh|anonfiles|gofile\.io|cdn\.discordapp\.com/attachments" +
                     @"|ngrok|trycloudflare\.com|\.onion\b", "payload_host", Severity.Medium, "Points at a host often used to serve payloads"),
            new Rule(@"(?i)CurrentVersion[\\/]+Run(Once)?\b", "autorun", Severity.High, "References the Windows startup (Run) key"),
            new Rule(@"(?i)Start Menu[\\/]+Programs[\\/]+Startup", "startup_folder", Severity.High, "References the Startup folder"),
            new Rule(@"(?i)vssadmin|delete shadows|bcdedit|wbadmin", "anti_recovery", Severity.Critical, "Deletes Windows backups/recovery"),
            new Rule(@"(?i)\.(exe|bat|cmd|ps1|vbs|scr|msi|hta)\b", "exe_strings", Severity.Low, "Mentions program/script file names"),
        };

        static readonly KeyValuePair<string, string>[] Obfuscators =
        {
            P("ConfusedByAttribute", "ConfuserEx"), P("DotfuscatorAttribute", "Dotfuscator"), P("SmartAssembly", "SmartAssembly"),
            P("BabelObfuscatorAttribute", "Babel"), P("ObfuscatedByGoliath", "Goliath"), P("Xenocode", "Xenocode"),
            P("NETGuard", ".NET Guard"), P("EazfuscatorAttribute", "Eazfuscator"), P("Agile.NET", "Agile.NET"),
        };

        static KeyValuePair<string, string> P(string a, string b) { return new KeyValuePair<string, string>(a, b); }

        sealed class Combo
        {
            public string[] Need, AnyOf;
            public string Rule, Desc;
            public Severity Sev;
            public Combo(string[] need, string[] anyOf, string rule, Severity sev, string desc)
            { Need = need; AnyOf = anyOf; Rule = rule; Sev = sev; Desc = desc; }
        }

        static readonly string[] Secrets = { "steam_secrets", "discord_token", "browser_secrets", "crypto_wallets", "dpapi" };

        static readonly Combo[] Combos =
        {
            new Combo(new[] { "network", "loads_code_bytes" }, new string[0], "loader", Severity.Critical,
                      "Downloads data and loads it as code (remote payload loader)"),
            new Combo(new[] { "network", "compiles_code" }, new string[0], "remote_compile", Severity.Critical,
                      "Downloads data and compiles it as code (remote payload loader)"),
            // Process.Start + internet alone is usually "open a web page"; a dropper also needs something to launch.
            new Combo(new[] { "network", "exec" }, new[] { "exe_strings", "temp_path", "lolbin" }, "dropper", Severity.Critical,
                      "Downloads something and starts a program (dropper pattern)"),
            new Combo(new string[0], Secrets, "stealer_targets", Severity.High, "Looks for account secrets"),
            new Combo(new[] { "network" }, Secrets, "stealer", Severity.Critical,
                      "Reads account secrets and can send them over the internet (stealer pattern)"),
            new Combo(new string[0], new[] { "exfil_discord", "exfil_telegram" }, "exfil_with_secrets_or_files", Severity.Critical, ""),
            new Combo(new[] { "workshop_publish" }, new[] { "user_folders", "enumerates_files", "network", "friend_messages" }, "worm",
                      Severity.Critical, "Can republish Workshop items and touch other files/accounts (self-spreading pattern)"),
            new Combo(new[] { "base64", "loads_code_bytes" }, new string[0], "packed_loader", Severity.High,
                      "Decodes hidden data and loads it as code"),
            new Combo(new[] { "base64", "writes_files", "exec" }, new[] { "exe_strings", "temp_path", "lolbin" }, "embedded_dropper",
                      Severity.High, "Decodes hidden data, writes it to disk and can start programs"),
            new Combo(new[] { "deletes_dirs", "enumerates_files", "user_folders" }, new string[0], "wiper", Severity.High,
                      "Walks user folders and deletes directories (file-wiper pattern)"),
            new Combo(new[] { "lolbin" }, new[] { "exec" }, "lolbin_exec", Severity.Critical,
                      "Runs a Windows system tool (cmd/powershell/...) as a payload"),
        };

        /// <summary>Findings for one .NET assembly, plus the capabilities seen (for logs and tests).</summary>
        public static List<Finding> Analyze(byte[] data, string file, out SortedSet<string> capabilities)
        {
            capabilities = new SortedSet<string>(StringComparer.Ordinal);
            var findings = new List<Finding>();
            PeFile pe = PeFile.TryRead(data);
            Metadata md;
            try
            {
                if (pe == null || !pe.IsDotNet) return findings;
                md = Metadata.Read(pe);
            }
            catch (FormatException e)
            {
                findings.Add(new Finding("dotnet", Severity.Low, "dotnet.unparseable", "Could not parse .NET metadata (" + e.Message + ")", file));
                return findings;
            }

            var byCap = new Dictionary<string, Finding>();
            var caps = capabilities;
            Action<string, Severity, string, string, string> add = (cap, sev, desc, ev, prefix) =>
            {
                Finding f;
                if (!byCap.TryGetValue(cap, out f))
                {
                    f = sev != Severity.Info ? new Finding("dotnet", sev, prefix + "." + cap, desc, file) : null;
                    byCap[cap] = f;
                    caps.Add(cap);
                    if (f != null) findings.Add(f);
                }
                if (f != null && f.Evidence.Count < 6 && !f.Evidence.Contains(ev)) f.Evidence.Add(ev);
            };

            try
            {
                foreach (var mr in md.MemberRefs())
                {
                    foreach (var r in Calls)
                    {
                        if (!r.Rx.IsMatch(mr.Key)) continue;
                        if (r.Cap == "loads_code" && TakesByteArray(mr.Value))
                            add("loads_code_bytes", Severity.Medium, "Loads code straight from memory (Assembly.Load(byte[]))", mr.Key, "dotnet");
                        else
                            add(r.Cap, r.Sev, r.Desc, mr.Key, "dotnet");
                    }
                }
                foreach (var pi in md.PInvokes())
                    foreach (var r in PInvoke)
                        if (r.Dll.IsMatch(pi.Key) && r.Rx.IsMatch(pi.Value))
                            add(r.Cap, r.Sev, r.Desc, pi.Key + "!" + pi.Value, "dotnet.pinvoke");
                foreach (var s in md.UserStrings())
                    foreach (var r in Strings)
                        if (r.Rx.IsMatch(s))
                            add(r.Cap, r.Sev, r.Desc, s.Length > 160 ? s.Substring(0, 160) : s, "dotnet.string");

                var names = new HashSet<string>(md.TypeNames());
                var obf = Obfuscators.FirstOrDefault(o => names.Any(n => n.Contains(o.Key)));
                if (obf.Key != null)
                    add("obfuscated", Severity.High, "Obfuscated with " + obf.Value + ": the code is deliberately hidden from review", obf.Key, "dotnet");
                else
                {
                    var weird = names.Where(n => n.Length > 0 && n.Any(ch => ch > 127)).ToList();
                    if (weird.Count >= 10)
                        findings.Add(new Finding("dotnet", Severity.Medium, "dotnet.obfuscated_names",
                                                 "Many type names are unreadable symbols (typical of obfuscation)", file, weird.Take(5)));
                }
                foreach (var res in md.EmbeddedResources())
                    if (res.Value.Length >= 2 && res.Value[0] == (byte)'M' && res.Value[1] == (byte)'Z')
                        add("embedded_pe", Severity.Medium, "Carries another program inside its resources", res.Key, "dotnet");
            }
            catch (Exception e) when (e is IndexOutOfRangeException || e is ArgumentException || e is FormatException)
            {
                findings.Add(new Finding("dotnet", Severity.Low, "dotnet.unparseable", "Could not fully parse .NET metadata (" + e.Message + ")", file));
            }

            foreach (var c in Combos)
            {
                if (!c.Need.All(caps.Contains) || (c.AnyOf.Length > 0 && !c.AnyOf.Any(caps.Contains))) continue;
                if (c.Rule == "exfil_with_secrets_or_files")
                {
                    if (new[] { "steam_secrets", "discord_token", "browser_secrets", "crypto_wallets", "enumerates_files" }.Any(caps.Contains))
                        findings.Add(new Finding("dotnet", Severity.Critical, "dotnet.combo.exfil",
                                                 "Has a hard-coded chat webhook/bot and reads secrets or files (exfiltration)", file,
                                                 new[] { "exfil_discord", "exfil_telegram" }.Where(caps.Contains)));
                    continue;
                }
                findings.Add(new Finding("dotnet", c.Sev, "dotnet.combo." + c.Rule, c.Desc, file,
                                         c.Need.Concat(c.AnyOf).Where(caps.Contains).OrderBy(x => x, StringComparer.Ordinal)));
            }
            return findings;
        }

        // --- method signatures: is this Assembly.Load(byte[]) rather than Load(string)? ---------------------------

        static int SkipType(byte[] b, int i)
        {
            byte t = b[i++];
            if (t == 0x11 || t == 0x12 || t == 0x13 || t == 0x1E) { Metadata.CompressedUInt(b, ref i); return i; }
            if (t == 0x0F || t == 0x10 || t == 0x1D || t == 0x45) return SkipType(b, i);
            if (t == 0x15)
            {
                i++;
                Metadata.CompressedUInt(b, ref i);
                int n = Metadata.CompressedUInt(b, ref i);
                for (int k = 0; k < n; k++) i = SkipType(b, i);
            }
            return i;
        }

        internal static bool TakesByteArray(byte[] sig)
        {
            try
            {
                int i = 1;
                if ((sig[0] & 0x10) != 0) Metadata.CompressedUInt(sig, ref i);
                int n = Metadata.CompressedUInt(sig, ref i);
                i = SkipType(sig, i);
                for (int k = 0; k < n; k++)
                {
                    if (sig[i] == 0x1D && sig[i + 1] == 0x05) return true;
                    i = SkipType(sig, i);
                }
            }
            catch (IndexOutOfRangeException) { }
            return false;
        }
    }
}
