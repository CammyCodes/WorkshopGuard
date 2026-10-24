using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using WorkshopGuard;
using Xunit;

// dotnet test modguard/tests/ModGuard.Tests
public class ModGuardTests : IDisposable
{
    static readonly string Repo = FindRepo();
    static readonly string Stealer = Path.Combine(Repo, "tests", "fixtures", "out", "plateup", "9000000001", "FakeStealerMod.dll");
    readonly string tmp = Path.Combine(Path.GetTempPath(), "modguard-tests-" + Guid.NewGuid().ToString("N"));

    static string FindRepo()
    {
        var d = new DirectoryInfo(AppContext.BaseDirectory);
        while (d != null && !File.Exists(Path.Combine(d.FullName, "gate.pyw"))) d = d.Parent;
        return d == null ? "" : d.FullName;
    }

    public void Dispose()
    {
        try { Directory.Delete(tmp, true); } catch (IOException) { }
    }

    string Mod(string name, Dictionary<string, byte[]> files)
    {
        var d = Path.Combine(tmp, "mods", name);
        foreach (var kv in files)
        {
            var p = Path.Combine(d, kv.Key);
            Directory.CreateDirectory(Path.GetDirectoryName(p));
            File.WriteAllBytes(p, kv.Value);
        }
        return d;
    }

    ModGuard Guard(bool av = false, params string[] blocklists)
    {
        return new ModGuard(new ModGuardOptions
        {
            CacheDirectory = Path.Combine(tmp, "cache"),
            UseWindowsAntivirus = av,
            Blocklists = blocklists.ToList(),
        });
    }

    static byte[] Bytes(string s) { return Encoding.UTF8.GetBytes(s); }

    static Dictionary<string, byte[]> CleanFiles()
    {
        return new Dictionary<string, byte[]> { { "Mod.assets", Bytes("UnityFS fake bundle") }, { "readme.txt", Bytes("hi") } };
    }

    // --- verdicts ---------------------------------------------------------------------------------------------

    [Fact]
    public void Clean_mod_is_allowed()
    {
        using (var g = Guard())
        {
            var c = g.CheckFolder(Mod("1001", CleanFiles()), 1001);
            Assert.Equal(Verdict.Clean, c.Verdict);
            Assert.True(c.Allowed);
            Assert.Equal(2, c.Sha256.Count);
        }
    }

    [Fact]
    public void Fake_stealer_is_malicious_and_refused()
    {
        if (!File.Exists(Stealer)) return;   // fixture not built on this machine
        using (var g = Guard())
        {
            var c = g.CheckFolder(Mod("9000000001", new Dictionary<string, byte[]> { { "FakeStealerMod.dll", File.ReadAllBytes(Stealer) } }), 9000000001);
            Assert.Equal(Verdict.Malicious, c.Verdict);
            Assert.False(c.Allowed);
            var rules = c.Findings.Select(f => f.Rule).ToList();
            Assert.Contains("dotnet.combo.stealer", rules);
            Assert.Contains("dotnet.combo.loader", rules);
            Assert.Contains("dotnet.combo.worm", rules);
        }
    }

    [Fact]
    public void Stealer_hidden_in_a_zip_is_found()
    {
        if (!File.Exists(Stealer)) return;
        var ms = new MemoryStream();
        using (var z = new ZipArchive(ms, ZipArchiveMode.Create, true))
        using (var e = z.CreateEntry("inner/FakeStealerMod.dll").Open())
        {
            var b = File.ReadAllBytes(Stealer);
            e.Write(b, 0, b.Length);
        }
        using (var g = Guard())
        {
            var c = g.CheckFolder(Mod("1002", new Dictionary<string, byte[]> { { "extras.zip", ms.ToArray() } }));
            Assert.Equal(Verdict.Malicious, c.Verdict);
            Assert.Contains(c.Findings, f => f.File == "extras.zip!inner/FakeStealerMod.dll");
        }
    }

    [Fact]
    public void Program_disguised_as_an_image_is_malicious()
    {
        var pe = File.ReadAllBytes(typeof(ModGuard).Assembly.Location);
        using (var g = Guard())
        {
            var c = g.CheckFolder(Mod("1003", new Dictionary<string, byte[]> { { "preview.png", pe }, { "notes.txt.bat", Bytes("@echo off") } }));
            Assert.Equal(Verdict.Malicious, c.Verdict);
            Assert.Contains(c.Findings, f => f.Rule == "files.disguised_executable");
            Assert.Contains(c.Findings, f => f.Rule == "files.double_extension");
        }
    }

    [Fact]
    public void Batch_file_is_suspicious_but_allowed_unless_asked()
    {
        var files = new Dictionary<string, byte[]> { { "setup.bat", Bytes("@echo off") } };
        using (var g = Guard())
            Assert.True(g.CheckFolder(Mod("1004", files)).Allowed);
        var strict = new ModGuard(new ModGuardOptions { BlockSuspicious = true, UseWindowsAntivirus = false });
        var c = strict.CheckFolder(Mod("1005", files));
        Assert.Equal(Verdict.Suspicious, c.Verdict);
        Assert.False(c.Allowed);
    }

    // --- memory ----------------------------------------------------------------------------------------------

    [Fact]
    public void Second_launch_reads_results_from_the_cache()
    {
        var d = Mod("1001", CleanFiles());
        using (var g = Guard()) Assert.Equal(2, g.CheckFolder(d).FilesScanned);
        using (var g = Guard())
        {
            var c = g.CheckFolder(d);
            Assert.Equal(0, c.FilesScanned);
            Assert.Equal(2, c.FilesFromCache);
        }
        File.WriteAllBytes(Path.Combine(d, "readme.txt"), Bytes("changed"));
        using (var g = Guard()) Assert.Equal(1, g.CheckFolder(d).FilesScanned);
    }

    [Fact]
    public void Same_payload_under_a_new_item_id_is_known_bad()
    {
        if (!File.Exists(Stealer)) return;
        var files = new Dictionary<string, byte[]> { { "FakeStealerMod.dll", File.ReadAllBytes(Stealer) } };
        using (var g = Guard()) g.CheckFolder(Mod("9000000001", files), 9000000001);
        using (var g = Guard())
        {
            var c = g.CheckFolder(Mod("9000000777", new Dictionary<string, byte[]> { { "Renamed.dll", files["FakeStealerMod.dll"] } }), 9000000777);
            Assert.Contains(c.Findings, f => f.Rule == "gate.known_bad");
        }
    }

    [Fact]
    public void A_file_shared_with_a_clean_mod_is_never_marked_bad()
    {
        if (!File.Exists(Stealer)) return;
        var harmony = Bytes("pretend this is 0Harmony.dll");
        using (var g = Guard())
        {
            g.CheckFolder(Mod("1001", new Dictionary<string, byte[]> { { "0Harmony.txt", harmony } }));
            g.CheckFolder(Mod("9000000001", new Dictionary<string, byte[]> { { "FakeStealerMod.dll", File.ReadAllBytes(Stealer) }, { "0Harmony.txt", harmony } }));
            var c = g.CheckFolder(Mod("1002", new Dictionary<string, byte[]> { { "0Harmony.txt", harmony } }));
            Assert.Equal(Verdict.Clean, c.Verdict);
        }
    }

    // --- blocklists ------------------------------------------------------------------------------------------

    [Fact]
    public void Blocklisted_item_and_file_hash_are_refused()
    {
        var files = CleanFiles();
        string sha;
        using (var h = SHA256.Create()) sha = BitConverter.ToString(h.ComputeHash(files["Mod.assets"])).Replace("-", "").ToLowerInvariant();
        var bl = Path.Combine(tmp, "blocklist.json");
        Directory.CreateDirectory(tmp);
        File.WriteAllText(bl, "{\"appid\":1599600,\"items\":[{\"id\":\"4242\",\"title\":\"Bad Mod\",\"reason\":\"steals logins\",\"sha256\":[\"" + sha + "\"]}],\"sha256\":[\"" + sha + "\"]}");
        using (var g = Guard(false, bl))
        {
            var byId = g.CheckFolder(Mod("4242", new Dictionary<string, byte[]> { { "x.txt", Bytes("x") } }), 4242);
            Assert.False(byId.Allowed);
            Assert.Contains(byId.Findings, f => f.Rule == "blocklist.item");
            var byHash = g.CheckFolder(Mod("5000", files), 5000);
            Assert.False(byHash.Allowed);
            Assert.Contains(byHash.Findings, f => f.Rule == "blocklist.listed" && f.Description.Contains("steals logins"));
        }
    }

    [Fact]
    public void Unreachable_blocklist_falls_back_to_the_last_copy()
    {
        var bl = Path.Combine(tmp, "blocklist.json");
        Directory.CreateDirectory(tmp);
        File.WriteAllText(bl, "{\"items\":[{\"id\":\"4242\",\"sha256\":[]}],\"sha256\":[]}");
        using (var g = Guard(false, bl)) g.CheckFolder(Mod("1", CleanFiles()));
        File.Delete(bl);   // the server is down now
        using (var g = Guard(false, bl))
            Assert.False(g.CheckFolder(Mod("4242", CleanFiles()), 4242).Allowed);
    }

    // --- loading exactly what was checked --------------------------------------------------------------------

    [Fact]
    public void ReadChecked_refuses_a_file_changed_after_the_check()
    {
        var d = Mod("1001", CleanFiles());
        using (var g = Guard())
        {
            g.CheckFolder(d);
            var p = Path.Combine(d, "Mod.assets");
            Assert.Equal(File.ReadAllBytes(p), g.ReadChecked(p));
            File.WriteAllBytes(p, Bytes("swapped after the check"));
            Assert.Throws<InvalidOperationException>(() => g.ReadChecked(p));
            Assert.Throws<InvalidOperationException>(() => g.ReadChecked(Path.Combine(d, "never-checked.dll")));
        }
    }

    // --- the player's antivirus ------------------------------------------------------------------------------

    [Fact]
    public void Windows_antivirus_flags_the_AMSI_test_sample()
    {
        using (var av = new WindowsAntivirus("ModGuard tests"))
        {
            if (!av.Available) return;   // not Windows 10+, or no AMSI provider
            // Microsoft's harmless AMSI test string, stored reversed so this source file isn't itself flagged
            var sample = new string("6831c4841ca0-0478-9334-b168-ec3c27e7 :elpmaS tseT ISMA".Reverse().ToArray());
            Assert.Equal(WindowsAntivirus.Result.Detected, av.Scan(Encoding.Unicode.GetBytes(sample), "amsi-test"));
            Assert.Equal(WindowsAntivirus.Result.Clean, av.Scan(Bytes("just some mod text"), "clean-test"));
        }
    }

    [Fact]
    public void Antivirus_detection_makes_the_mod_malicious()
    {
        using (var g = Guard(true))
        {
            if (!new WindowsAntivirus("probe").Available) return;
            var sample = new string("6831c4841ca0-0478-9334-b168-ec3c27e7 :elpmaS tseT ISMA".Reverse().ToArray());
            var d = Mod("1006", new Dictionary<string, byte[]> { { "script.txt", Encoding.Unicode.GetBytes(sample) } });
            var c = g.CheckFolder(d);
            // real-time protection usually refuses to even open the file; otherwise AMSI flags its bytes
            Assert.Contains(c.Findings, f => f.Rule == "antivirus.detected" || f.Rule == "antivirus.blocked_read");
            Assert.Equal(Verdict.Malicious, c.Verdict);
            Assert.False(c.Allowed);
        }
    }

    // --- pieces ----------------------------------------------------------------------------------------------

    [Fact]
    public void Real_framework_assembly_parses_without_errors()
    {
        SortedSet<string> caps;
        var f = ModGuard.AnalyzeBytes("System.Net.Http.dll", File.ReadAllBytes(typeof(System.Net.Http.HttpClient).Assembly.Location), null, out caps);
        Assert.DoesNotContain(f, x => x.Rule == "dotnet.unparseable");
    }
}
