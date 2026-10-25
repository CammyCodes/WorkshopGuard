// WorkshopGuard ModGuard: check mods before a Unity/C# game loads them. MIT licence, github.com/CammyCodes/WorkshopGuard
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace WorkshopGuard
{
    public sealed class ModGuardOptions
    {
        /// <summary>Where results are remembered between launches (Application.persistentDataPath/WorkshopGuard).
        /// Null = check everything every time.</summary>
        public string CacheDirectory;

        /// <summary>WorkshopGuard blocklists (http(s) URLs or file paths): banned item IDs and the hashes of their
        /// bad files. A source that can't be reached falls back to its last good copy (up to 30 days old).</summary>
        public List<string> Blocklists = new List<string>();
        public int BlocklistTimeoutMs = 3000;

        /// <summary>Also ask the player's antivirus (Windows AMSI: Microsoft Defender and most others).</summary>
        public bool UseWindowsAntivirus = true;

        /// <summary>Refuse "suspicious" mods too, not only "malicious" ones. Off by default: suspicious means
        /// "a person should look", and legitimate mods sometimes do unusual things.</summary>
        public bool BlockSuspicious = false;

        public GameProfile Profile = GameProfile.UnityCSharp();

        /// <summary>Bigger files are hashed in full but only their first part is analysed.</summary>
        public int MaxScanBytes = 256 * 1024 * 1024;

        /// <summary>Where ModGuard's log lines go (Debug.Log in Unity).</summary>
        public Action<string> Log;

        /// <summary>Starts every log line. Your product's name: nothing ModGuard says to players names WorkshopGuard.</summary>
        public string LogPrefix = "[WorkshopGuard] ";

        /// <summary>The name the player's antivirus sees in its logs when ModGuard asks it to scan.</summary>
        public string ProductName = "WorkshopGuard ModGuard";
    }

    /// <summary>Checks mod folders before the game loads them: every file hashed, anything new analysed (.NET code,
    /// file types, native programs, the player's antivirus), known-bad files and blocklisted items refused. Results
    /// are cached per file hash, so an unchanged mod costs only its hashing time on later launches.
    /// <code>
    /// var guard = new ModGuard(new ModGuardOptions { CacheDirectory = ..., Log = Debug.Log });
    /// guard.Prepare();                                   // early in start-up: loads the cache, fetches blocklists
    /// ModCheck c = guard.CheckFolder(folder, itemId);    // per mod, before loading it
    /// if (!c.Allowed) { /* skip it and tell the player c.Summary() */ }
    /// guard.Save();                                      // after loading mods
    /// </code></summary>
    public sealed class ModGuard : IDisposable
    {
        public const string Version = "1.0.0";
        /// <summary>Changes whenever a rule changes, so cached results from older rules are thrown away.</summary>
        public const string EngineId = "modguard-1.0.0/dotnet-rules-2026-10-25";

        readonly ModGuardOptions o;
        readonly object gate = new object();
        Dictionary<string, object> fileCache = new Dictionary<string, object>();   // "sha|name" -> findings
        Dictionary<string, object> bad = new Dictionary<string, object>();         // sha -> reason
        HashSet<string> clean = new HashSet<string>();                             // hashes seen in clean mods
        Dictionary<string, object> blocklistCopies = new Dictionary<string, object>();
        readonly HashSet<string> blockedIds = new HashSet<string>();
        readonly Dictionary<string, string> blockedHashes = new Dictionary<string, string>();
        readonly Dictionary<string, string> checkedHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        readonly List<ModCheck> results = new List<ModCheck>();
        readonly ManualResetEvent blocklistsReady = new ManualResetEvent(false);
        WindowsAntivirus av;
        bool prepared, dirty;

        public ModGuard(ModGuardOptions options) { o = options ?? new ModGuardOptions(); }

        public IList<ModCheck> Results { get { lock (gate) return results.ToList(); } }
        public bool AntivirusAvailable { get { return av != null && av.Available; } }

        void Log(string s) { var l = o.Log; if (l != null) l(o.LogPrefix + s); }

        // --- start-up --------------------------------------------------------------------------------------------

        /// <summary>Loads remembered results and starts fetching blocklists in the background. Call it as early as
        /// you can; <see cref="CheckFolder"/> calls it if you didn't.</summary>
        public void Prepare()
        {
            lock (gate)
            {
                if (prepared) return;
                prepared = true;
                LoadCache();
                if (o.UseWindowsAntivirus)
                {
                    av = new WindowsAntivirus(o.ProductName);
                    if (!av.Available) Log("player's antivirus not used: " + av.Problem);
                }
            }
            if (o.Blocklists.Count == 0) { blocklistsReady.Set(); return; }
            var t = new Thread(FetchBlocklists) { IsBackground = true, Name = "ModGuard blocklists" };
            t.Start();
        }

        string CachePath { get { return o.CacheDirectory == null ? null : Path.Combine(o.CacheDirectory, "modguard-cache.json"); } }

        void LoadCache()
        {
            var path = CachePath;
            if (path == null || !File.Exists(path)) return;
            try
            {
                var root = MiniJson.Parse(File.ReadAllText(path, Encoding.UTF8)) as Dictionary<string, object>;
                if (root == null) return;
                object v;
                if (root.TryGetValue("engine", out v) && (v as string) == EngineId && root.TryGetValue("files", out v))
                    fileCache = v as Dictionary<string, object> ?? fileCache;   // results from other rules are dropped
                if (root.TryGetValue("bad", out v)) bad = v as Dictionary<string, object> ?? bad;
                if (root.TryGetValue("clean", out v) && v is List<object>) clean = new HashSet<string>(((List<object>)v).OfType<string>());
                if (root.TryGetValue("blocklists", out v)) blocklistCopies = v as Dictionary<string, object> ?? blocklistCopies;
            }
            catch (Exception e) when (e is IOException || e is FormatException || e is UnauthorizedAccessException ||
                                      e is IndexOutOfRangeException || e is ArgumentException)
            {
                Log("cache unreadable, starting fresh: " + e.Message);
            }
        }

        /// <summary>Remembers results for next time. Call after mods are loaded (and from <see cref="Dispose"/>).</summary>
        public void Save()
        {
            var path = CachePath;
            if (path == null) return;
            string json;
            lock (gate)
            {
                if (!dirty) return;
                json = MiniJson.Write(new Dictionary<string, object>
                {
                    { "engine", EngineId }, { "files", fileCache }, { "bad", bad }, { "clean", clean.ToList() },
                    { "blocklists", blocklistCopies },
                });
                dirty = false;
            }
            try
            {
                Directory.CreateDirectory(o.CacheDirectory);
                var tmp = path + ".tmp";
                File.WriteAllText(tmp, json, new UTF8Encoding(false));
                if (File.Exists(path)) File.Delete(path);
                File.Move(tmp, path);
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException)
            {
                Log("couldn't save results: " + e.Message);
            }
        }

        // --- blocklists ------------------------------------------------------------------------------------------

        void FetchBlocklists()
        {
            try
            {
                foreach (var src in o.Blocklists)
                {
                    string body = null;
                    try
                    {
                        body = Fetch(src);
                        lock (gate)
                        {
                            blocklistCopies[src] = new Dictionary<string, object> { { "at", (double)Now() }, { "body", body } };
                            dirty = true;
                        }
                    }
                    catch (Exception e)
                    {
                        object copy;
                        lock (gate) blocklistCopies.TryGetValue(src, out copy);
                        var c = copy as Dictionary<string, object>;
                        if (c != null && c.ContainsKey("at") && Now() - Convert.ToDouble(c["at"]) < 30 * 86400)
                        {
                            body = c["body"] as string;
                            Log("blocklist " + src + " unreachable (" + e.Message + "), using the copy from " +
                                Math.Round((Now() - Convert.ToDouble(c["at"])) / 3600.0, 1) + " h ago");
                        }
                        else Log("blocklist " + src + " unreachable and no recent copy: " + e.Message);
                    }
                    if (body != null) LoadBlocklist(src, body);
                }
            }
            finally { blocklistsReady.Set(); }
        }

        string Fetch(string src)
        {
            if (!src.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !src.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                return File.ReadAllText(src, Encoding.UTF8);
            var req = (HttpWebRequest)WebRequest.Create(src);
            req.Timeout = req.ReadWriteTimeout = o.BlocklistTimeoutMs;
            req.UserAgent = "ModGuard/" + Version;
            using (var resp = (HttpWebResponse)req.GetResponse())
            using (var r = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                return r.ReadToEnd();
        }

        void LoadBlocklist(string src, string body)
        {
            try
            {
                var root = MiniJson.Parse(body) as Dictionary<string, object>;
                if (root == null) return;
                int ids = 0, hashes = 0;
                lock (gate)
                {
                    object items;
                    if (root.TryGetValue("items", out items) && items is List<object>)
                        foreach (var it in ((List<object>)items).OfType<Dictionary<string, object>>())
                        {
                            object id, title, reason, list;
                            it.TryGetValue("id", out id);
                            it.TryGetValue("title", out title);
                            it.TryGetValue("reason", out reason);
                            string why = "'" + (title ?? id) + "' " + (string.IsNullOrEmpty(reason as string) ? "banned" : reason);
                            if (id != null) { blockedIds.Add(Convert.ToString(id, System.Globalization.CultureInfo.InvariantCulture)); ids++; }
                            if (it.TryGetValue("sha256", out list) && list is List<object>)
                                foreach (var h in ((List<object>)list).OfType<string>()) { blockedHashes[h.ToLowerInvariant()] = why; hashes++; }
                        }
                    object top;
                    if (root.TryGetValue("sha256", out top) && top is List<object>)
                        foreach (var h in ((List<object>)top).OfType<string>())
                            if (!blockedHashes.ContainsKey(h.ToLowerInvariant())) { blockedHashes[h.ToLowerInvariant()] = "listed as malware"; hashes++; }
                }
                Log("blocklist " + src + ": " + ids + " banned items, " + hashes + " file hashes");
            }
            catch (FormatException e) { Log("blocklist " + src + " isn't valid JSON: " + e.Message); }
        }

        static long Now() { return (long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds; }

        // --- checking --------------------------------------------------------------------------------------------

        /// <summary>Checks every file in a mod folder (subfolders too: a mod's code can read anything in its folder).
        /// <paramref name="itemId"/> is the Workshop item ID, or 0 for a local mod.</summary>
        public ModCheck CheckFolder(string folder, ulong itemId = 0)
        {
            Prepare();
            blocklistsReady.WaitOne(o.BlocklistTimeoutMs + 500);
            var sw = Stopwatch.StartNew();
            var check = new ModCheck { Folder = folder, ItemId = itemId };
            lock (gate)
            {
                if (itemId != 0 && blockedIds.Contains(itemId.ToString()))
                    check.Findings.Add(new Finding("blocklist", Severity.Critical, "blocklist.item",
                        "This Workshop item is on the blocklist of banned mods", ""));
                foreach (var file in Walk(folder, "", check.Findings))
                    CheckFile(folder, file, check);
                int score;
                check.Verdict = Verdicts.For(check.Findings, out score);
                check.Score = score;
                check.Allowed = check.Verdict == Verdict.Clean || (check.Verdict == Verdict.Suspicious && !o.BlockSuspicious);
                if (check.Verdict == Verdict.Malicious) RememberBad(check);
                else if (check.Verdict == Verdict.Clean) clean.UnionWith(check.Sha256.Values);
                check.Milliseconds = sw.Elapsed.TotalMilliseconds;
                results.Add(check);
                dirty = true;
            }
            Log((itemId != 0 ? "item " + itemId : Path.GetFileName(folder.TrimEnd('/', '\\'))) + ": " + check.Summary() + " (" +
                check.Sha256.Count + " files, " + check.FilesScanned + " analysed, " + Math.Round(check.Milliseconds) + " ms)");
            return check;
        }

        IEnumerable<string> Walk(string root, string prefix, List<Finding> notes)
        {
            var dir = new DirectoryInfo(prefix.Length == 0 ? root : Path.Combine(root, prefix));
            FileSystemInfo[] entries;
            try { entries = dir.GetFileSystemInfos(); }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException)
            {
                notes.Add(new Finding("files", Severity.Medium, "files.unreadable_dir", "Folder can't be read (" + e.Message + ")", prefix));
                yield break;
            }
            foreach (var e in entries.OrderBy(x => x.Name, StringComparer.Ordinal))
            {
                string rel = prefix.Length == 0 ? e.Name : prefix + "/" + e.Name;
                if ((e.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    notes.Add(new Finding("files", Severity.Medium, "files.symlink", "Link to somewhere outside the mod", rel));
                    continue;
                }
                if ((e.Attributes & FileAttributes.Directory) != 0)
                {
                    foreach (var f in Walk(root, rel, notes)) yield return f;
                }
                else yield return rel;
            }
        }

        void CheckFile(string folder, string rel, ModCheck check)
        {
            string full = Path.Combine(folder, rel.Replace('/', Path.DirectorySeparatorChar));
            byte[] data;
            string sha;
            try { data = ReadAndHash(full, out sha); }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException)
            {
                // ERROR_VIRUS_INFECTED / ERROR_VIRUS_DELETED: the player's antivirus refused to open it
                int code = e.HResult & 0xFFFF;
                if (code == 225 || code == 226)
                    check.Findings.Add(new Finding("antivirus", Severity.Critical, "antivirus.blocked_read",
                        "Your antivirus blocked this file: it contains a virus or unwanted software", rel));
                else
                    check.Findings.Add(new Finding("files", Severity.Low, "files.unreadable", "Could not read (" + e.Message + ")", rel));
                return;
            }
            check.Sha256[rel] = sha;
            checkedHashes[Path.GetFullPath(full)] = sha;

            object reason;
            if (bad.TryGetValue(sha, out reason))
                check.Findings.Add(new Finding("known-bad", Severity.Critical, "gate.known_bad", "Known malicious file (" + reason + ")", rel));
            string listed;
            if (blockedHashes.TryGetValue(sha, out listed))
                check.Findings.Add(new Finding("blocklist", Severity.Critical, "blocklist.listed", "On the blocklist of banned mods: " + listed, rel));

            string name = rel.Substring(rel.LastIndexOf('/') + 1).ToLowerInvariant();
            string key = sha + "|" + name;
            object cached;
            if (fileCache.TryGetValue(key, out cached) && cached is List<object>)
            {
                check.FilesFromCache++;
                check.Findings.AddRange(((List<object>)cached).OfType<Dictionary<string, object>>().Select(f => FromJson(f, rel)));
                return;
            }
            check.FilesScanned++;
            var caps = new SortedSet<string>(StringComparer.Ordinal);
            var found = FileChecks.Check(rel, data, o.Profile, caps);
            bool complete = true;
            if (av != null && av.Available)
            {
                var r = av.Scan(data, full);
                if (r == WindowsAntivirus.Result.Detected)
                    found.Add(new Finding("antivirus", Severity.Critical, "antivirus.detected", "Your antivirus flagged this file (Windows AMSI)", rel));
                else if (r == WindowsAntivirus.Result.BlockedByAdmin)
                    found.Add(new Finding("antivirus", Severity.High, "antivirus.blocked", "Your PC's security policy blocks this file", rel));
                else if (r == WindowsAntivirus.Result.Error)
                    complete = false;   // try again next launch rather than remember a half answer
            }
            check.Findings.AddRange(found);
            if (complete)
                fileCache[key] = found.Select(f => (object)ToJson(f, rel)).ToList();
        }

        byte[] ReadAndHash(string path, out string sha)
        {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var h = SHA256.Create())
            {
                if (fs.Length <= o.MaxScanBytes)
                {
                    var data = new byte[fs.Length];
                    int got = 0, n;
                    while (got < data.Length && (n = fs.Read(data, got, data.Length - got)) > 0) got += n;
                    sha = Hex(h.ComputeHash(data, 0, got));
                    return got == data.Length ? data : data.Take(got).ToArray();
                }
                var head = new byte[o.MaxScanBytes];
                int hg = 0, k;
                while (hg < head.Length && (k = fs.Read(head, hg, head.Length - hg)) > 0) hg += k;
                h.TransformBlock(head, 0, hg, null, 0);
                var buf = new byte[1 << 20];
                while ((k = fs.Read(buf, 0, buf.Length)) > 0) h.TransformBlock(buf, 0, k, null, 0);
                h.TransformFinalBlock(new byte[0], 0, 0);
                sha = Hex(h.Hash);
                return head;
            }
        }

        static string Hex(byte[] b)
        {
            var sb = new StringBuilder(b.Length * 2);
            foreach (var x in b) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }

        /// <summary>The bytes of a file, but only if they're exactly what <see cref="CheckFolder"/> checked. Load mods
        /// with this instead of File.ReadAllBytes and nothing can swap a file between the check and the load.</summary>
        public byte[] ReadChecked(string path)
        {
            string expected;
            lock (gate)
                if (!checkedHashes.TryGetValue(Path.GetFullPath(path), out expected))
                    throw new InvalidOperationException("This file was never checked: " + path);
            var data = File.ReadAllBytes(path);
            using (var h = SHA256.Create())
                if (Hex(h.ComputeHash(data)) != expected)
                    throw new InvalidOperationException("This file changed after it was checked: " + path);
            return data;
        }

        void RememberBad(ModCheck check)
        {
            // only the files that made it malicious, and never one that also ships in a clean mod (0Harmony.dll)
            var flagged = new HashSet<string>(check.Findings
                .Where(f => f.File.Length > 0 && f.Severity >= Severity.High)
                .Select(f => f.File.Split('!')[0]));
            if (flagged.Count == 0)
                flagged = new HashSet<string>(check.Sha256.Keys.Where(r => r.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)));
            string why = (check.Findings.FirstOrDefault(f => f.Severity == Severity.Critical) ?? check.Findings.FirstOrDefault())?.Description ?? "malicious";
            foreach (var rel in flagged)
            {
                string sha;
                if (check.Sha256.TryGetValue(rel, out sha) && !clean.Contains(sha))
                    bad[sha] = why.Length > 200 ? why.Substring(0, 200) : why;
            }
        }

        static Dictionary<string, object> ToJson(Finding f, string rel)
        {
            string file = f.File == rel ? "" : f.File.StartsWith(rel + "!", StringComparison.Ordinal) ? f.File.Substring(rel.Length) : f.File;
            return new Dictionary<string, object>
            {
                { "engine", f.Engine }, { "severity", (double)(int)f.Severity }, { "rule", f.Rule },
                { "description", f.Description }, { "file", file }, { "evidence", f.Evidence.Cast<object>().ToList() },
            };
        }

        static Finding FromJson(Dictionary<string, object> d, string rel)
        {
            string file = d["file"] as string ?? "";
            file = file.Length == 0 ? rel : file.StartsWith("!", StringComparison.Ordinal) ? rel + file : file;
            object ev;
            d.TryGetValue("evidence", out ev);
            return new Finding(d["engine"] as string, (Severity)(int)Convert.ToDouble(d["severity"]), d["rule"] as string,
                               d["description"] as string, file, (ev as List<object> ?? new List<object>()).OfType<string>());
        }

        /// <summary>Runs the file checks and .NET analysis on one file's bytes, with no caching, blocklists or
        /// antivirus: for tools and tests.</summary>
        public static List<Finding> AnalyzeBytes(string name, byte[] data, GameProfile profile, out SortedSet<string> capabilities)
        {
            capabilities = new SortedSet<string>(StringComparer.Ordinal);
            return FileChecks.Check(name, data, profile ?? GameProfile.UnityCSharp(), capabilities);
        }

        public void Dispose()
        {
            Save();
            if (av != null) av.Dispose();
        }
    }
}
