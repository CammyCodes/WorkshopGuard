// WorkshopGuard ModGuard: check mods before a Unity/C# game loads them. MIT licence, github.com/CammyCodes/WorkshopGuard
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.RegularExpressions;

namespace WorkshopGuard
{
    /// <summary>What a normal mod for the game looks like, so anything else stands out.</summary>
    public sealed class GameProfile
    {
        public string Name;
        public HashSet<string> ExpectedExtensions;   // file types a normal mod contains
        public HashSet<string> CodeExtensions;       // normal *code* for this game (scanned hard, not flagged for existing)
        public bool DllsExpected;

        static readonly string[] CommonAssets =
        {
            ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tga", ".dds", ".webp", ".txt", ".md", ".json", ".xml", ".ini",
            ".cfg", ".yml", ".yaml", ".csv", ".wav", ".ogg", ".mp3", ".flac", ".mp4", ".webm", ".ttf", ".otf", ".vdf", "",
        };

        /// <summary>PlateUp! and other Unity/C# games: a .NET DLL plus asset bundles.</summary>
        public static GameProfile UnityCSharp(string name = "PlateUp!")
        {
            return new GameProfile
            {
                Name = name,
                ExpectedExtensions = new HashSet<string>(CommonAssets.Concat(new[]
                    { ".dll", ".pdb", ".assets", ".bundle", ".assetbundle", ".manifest", ".mdb" }), StringComparer.OrdinalIgnoreCase),
                CodeExtensions = new HashSet<string>(new[] { ".dll" }, StringComparer.OrdinalIgnoreCase),
                DllsExpected = true,
            };
        }
    }

    /// <summary>File-level checks (names, types, disguised programs, archives) and native Windows program checks.
    /// Ported from WorkshopGuard's engine.py and pe.py.</summary>
    internal static class FileChecks
    {
        public static readonly HashSet<string> ExecutableExtensions = new HashSet<string>(new[]
        {
            ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
            ".hta", ".lnk", ".msi", ".msp", ".jar", ".reg", ".cpl", ".sh", ".appimage", ".elf", ".so", ".dylib", ".url",
            ".iso", ".img", ".vhd", ".vhdx",
        }, StringComparer.OrdinalIgnoreCase);

        static readonly HashSet<string> SafeLooking = new HashSet<string>(new[]
        {
            ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".txt", ".json", ".xml", ".wav", ".ogg", ".mp3", ".dds", ".tga", ".ff",
            ".bundle", ".assets", ".pdf", ".ini", ".cfg",
        }, StringComparer.OrdinalIgnoreCase);

        public static string Magic(byte[] d)
        {
            if (PeFile.LooksLikePe(d)) return "pe";
            if (StartsWith(d, 0x7F, (byte)'E', (byte)'L', (byte)'F')) return "elf";
            if (StartsWith(d, 0xCF, 0xFA, 0xED, 0xFE) || StartsWith(d, 0xFE, 0xED, 0xFA, 0xCF)) return "macho";
            if (StartsWith(d, (byte)'P', (byte)'K', 3, 4)) return "zip";
            if (StartsWith(d, (byte)'R', (byte)'a', (byte)'r', (byte)'!')) return "rar";
            if (StartsWith(d, (byte)'7', (byte)'z', 0xBC, 0xAF)) return "7z";
            if (StartsWith(d, (byte)'M', (byte)'S', (byte)'C', (byte)'F')) return "cab";
            if (StartsWith(d, 0xD0, 0xCF, 0x11, 0xE0)) return "ole";
            if (StartsWith(d, (byte)'L', 0, 0, 0)) return "lnk";
            if (StartsWith(d, (byte)'#', (byte)'!')) return "script";
            return "";
        }

        static bool StartsWith(byte[] d, params byte[] m)
        {
            if (d.Length < m.Length) return false;
            for (int i = 0; i < m.Length; i++) if (d[i] != m[i]) return false;
            return true;
        }

        /// <summary>Checks one file's bytes. <paramref name="capabilities"/> collects the .NET analyzer's view.</summary>
        public static List<Finding> Check(string rel, byte[] data, GameProfile p, SortedSet<string> capabilities, int depth = 0)
        {
            var found = new List<Finding>();
            string name = rel.Substring(rel.LastIndexOfAny(new[] { '/', '!' }) + 1);
            string ext = Path.GetExtension(name).ToLowerInvariant();
            string kind = Magic(data);

            var parts = name.ToLowerInvariant().Split('.');
            if (parts.Length >= 3 && ExecutableExtensions.Contains("." + parts[parts.Length - 1]) && SafeLooking.Contains("." + parts[parts.Length - 2]))
                found.Add(new Finding("files", Severity.Critical, "files.double_extension",
                    "Disguised file name: '" + name + "' pretends to be ." + parts[parts.Length - 2] + " but is ." + parts[parts.Length - 1], rel));
            if (kind == "pe" && SafeLooking.Contains(ext))
                found.Add(new Finding("files", Severity.Critical, "files.disguised_executable", "A Windows program hidden under a " + ext + " name", rel));
            if ((kind == "elf" || kind == "macho") && ext != ".so" && ext != ".dylib")
                found.Add(new Finding("files", Severity.High, "files.unix_executable", "Contains a " + kind.ToUpperInvariant() + " executable", rel));
            if (ExecutableExtensions.Contains(ext) && !p.CodeExtensions.Contains(ext) && !p.ExpectedExtensions.Contains(ext))
                found.Add(new Finding("files", ext == ".url" ? Severity.Medium : Severity.High, "files.executable_type",
                    "'" + ext + "' files can run code on your PC; " + p.Name + " mods don't need them", rel));
            if (kind == "pe" && !p.DllsExpected && !ExecutableExtensions.Contains(ext))
                found.Add(new Finding("files", Severity.High, "files.windows_code",
                    "Windows code (" + name + ") inside a " + p.Name + " mod; the game never loads these", rel));
            if (kind == "rar" || kind == "7z" || kind == "cab")
                found.Add(new Finding("files", Severity.Medium, "files.archive_not_unpacked",
                    kind.ToUpperInvariant() + " archive: its contents can't be inspected here", rel));

            if (kind == "pe")
            {
                var pe = PeFile.TryRead(data);
                if (pe == null)
                    found.Add(new Finding("pe", Severity.Medium, "pe.malformed", "Broken Windows executable header", rel));
                else if (pe.IsDotNet)
                {
                    SortedSet<string> caps;
                    found.AddRange(DotNetAnalyzer.Analyze(data, rel, out caps));
                    capabilities.UnionWith(caps);
                }
                else
                {
                    if (p.DllsExpected && ext == ".dll")
                        found.Add(new Finding("pe", Severity.Medium, "files.native_dll",
                            "Native (non-.NET) DLL in a " + p.Name + " mod; mods are normally .NET", rel));
                    found.AddRange(NativeProgram(pe, rel));
                }
            }
            if (kind == "zip") found.AddRange(Zip(rel, data, p, capabilities, depth));
            return found;
        }

        // --- native Windows programs (pe.py) -----------------------------------------------------------------------

        static readonly Tuple<Regex, Severity, string, string>[] Imports =
        {
            Imp(@"^(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread(Ex)?|NtUnmapViewOfSection|QueueUserAPC|SetThreadContext)$",
                Severity.High, "pe.injection", "Process-injection APIs"),
            Imp(@"^URLDownloadToFile\w*$", Severity.Critical, "pe.downloader", "Downloads files straight to disk"),
            Imp(@"^(InternetOpenUrl\w*|InternetReadFile|WinHttpOpen|WinHttpSendRequest|HttpSendRequest\w*)$", Severity.Medium,
                "pe.network", "Internet APIs"),
            Imp(@"^(WinExec|ShellExecute\w*|CreateProcess\w*)$", Severity.Medium, "pe.exec", "Starts other programs"),
            Imp(@"^(SetWindowsHookEx\w*|GetAsyncKeyState)$", Severity.High, "pe.keylogger", "Watches keystrokes"),
            Imp(@"^CryptUnprotectData$", Severity.High, "pe.dpapi", "Decrypts Windows-protected secrets (browser stealers)"),
            Imp(@"^(RegSetValueEx\w*|CreateService\w*)$", Severity.Medium, "pe.persistence", "Writes registry values / services"),
            Imp(@"^(IsDebuggerPresent|CheckRemoteDebuggerPresent)$", Severity.Low, "pe.antidebug", "Checks for a debugger"),
        };

        static Tuple<Regex, Severity, string, string> Imp(string rx, Severity s, string rule, string desc)
        {
            return Tuple.Create(new Regex(rx, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), s, rule, desc);
        }

        static readonly Dictionary<string, string> Packers = new Dictionary<string, string>
        {
            { "UPX0", "UPX" }, { "UPX1", "UPX" }, { ".aspack", "ASPack" }, { ".themida", "Themida" }, { ".vmp0", "VMProtect" },
            { ".vmp1", "VMProtect" }, { ".enigma1", "Enigma" }, { ".petite", "Petite" }, { "MPRESS1", "MPRESS" },
        };

        static List<Finding> NativeProgram(PeFile pe, string rel)
        {
            var found = new List<Finding>();
            var hits = new Dictionary<string, Finding>();
            foreach (var imp in pe.Imports())
                foreach (var r in Imports)
                    if (r.Item1.IsMatch(imp.Value))
                    {
                        Finding f;
                        if (!hits.TryGetValue(r.Item3, out f)) { f = new Finding("pe", r.Item2, r.Item3, r.Item4, rel); hits[r.Item3] = f; found.Add(f); }
                        if (f.Evidence.Count < 6) f.Evidence.Add(imp.Key + "!" + imp.Value);
                    }
            if ((hits.ContainsKey("pe.downloader") || hits.ContainsKey("pe.network")) && hits.ContainsKey("pe.exec"))
                found.Add(new Finding("pe", Severity.Critical, "pe.combo.dropper", "Downloads files and starts programs (dropper pattern)", rel));
            var packed = pe.Sections.FirstOrDefault(s => Packers.ContainsKey(s.Name));
            if (packed.Name != null)
                found.Add(new Finding("pe", Severity.High, "pe.packed", "Packed with " + Packers[packed.Name] + ": real code is hidden until it runs", rel, new[] { packed.Name }));
            else
            {
                var hi = pe.Sections.Where(s => s.RawSize > 4096 && (s.Characteristics & 0x20000000) != 0 && Entropy(pe.SectionData(s, 262144)) > 7.4)
                                    .Select(s => s.Name).ToList();
                if (hi.Count > 0)
                    found.Add(new Finding("pe", Severity.Medium, "pe.high_entropy_code", "Executable code section looks encrypted/compressed", rel, hi));
            }
            return found;
        }

        static double Entropy(byte[] b)
        {
            if (b.Length == 0) return 0;
            var counts = new int[256];
            foreach (var x in b) counts[x]++;
            double e = 0, n = b.Length;
            foreach (var c in counts) if (c > 0) e -= c / n * Math.Log(c / n, 2);
            return e;
        }

        // --- zip archives (engine.py's limits) ---------------------------------------------------------------------

        const int ZipMaxDepth = 3, ZipMaxMembers = 5000;
        const long ZipMaxTotal = 1024L * 1024 * 1024, ZipMaxMember = 256L * 1024 * 1024;

        static List<Finding> Zip(string rel, byte[] data, GameProfile p, SortedSet<string> caps, int depth)
        {
            var found = new List<Finding>();
            if (depth >= ZipMaxDepth)
            {
                found.Add(new Finding("files", Severity.Medium, "files.nested_archives", "Archives nested too deep", rel));
                return found;
            }
            try
            {
                using (var zf = new ZipArchive(new MemoryStream(data, false), ZipArchiveMode.Read))
                {
                    long total = 0;
                    int count = 0;
                    foreach (var e in zf.Entries)
                    {
                        if (e.FullName.EndsWith("/")) continue;
                        if (++count > ZipMaxMembers)
                        {
                            found.Add(new Finding("files", Severity.Medium, "files.zip_too_many", "Too many files in zip", rel));
                            break;
                        }
                        string member = rel + "!" + e.FullName;
                        if (e.CompressedLength > 0 && e.Length / Math.Max(e.CompressedLength, 1) > 200 && e.Length > (1L << 26))
                        {
                            found.Add(new Finding("files", Severity.High, "files.zip_bomb", "Zip bomb (absurd compression)", member));
                            continue;
                        }
                        total += e.Length;
                        if (total > ZipMaxTotal)
                        {
                            found.Add(new Finding("files", Severity.Low, "files.zip_truncated", "Zip too big to unpack fully", rel));
                            break;
                        }
                        byte[] blob;
                        try
                        {
                            using (var s = e.Open())
                            using (var ms = new MemoryStream())
                            {
                                var buf = new byte[81920];
                                int n;
                                while ((n = s.Read(buf, 0, buf.Length)) > 0 && ms.Length < ZipMaxMember) ms.Write(buf, 0, n);
                                blob = ms.ToArray();
                            }
                        }
                        catch (InvalidDataException ex)
                        {
                            // .NET reports encrypted entries as unsupported data; Python's zipfile flags them by bit
                            found.Add(new Finding("files", Severity.High, "files.encrypted_archive",
                                "Password-protected or unreadable file inside an archive (hides it from scanners): " + ex.Message, member));
                            continue;
                        }
                        found.AddRange(Check(member, blob, p, caps, depth + 1));
                    }
                }
            }
            catch (InvalidDataException e)
            {
                found.Add(new Finding("files", Severity.Low, "files.bad_zip", "Corrupt zip (" + e.Message + ")", rel));
            }
            catch (TypeLoadException)
            {
                found.Add(new Finding("files", Severity.Medium, "files.archive_not_unpacked", "Zip archive: its contents can't be inspected here", rel));
            }
            return found;
        }
    }
}
