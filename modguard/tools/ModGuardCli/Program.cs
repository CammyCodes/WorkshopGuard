using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using WorkshopGuard;

// modguard check <folder>... [--cache DIR] [--blocklist URL] [--no-av]   check mod folders like the game would
// modguard analyze <file>...                                               one JSON line per file (for parity tests)
static class Program
{
    static int Main(string[] args)
    {
        if (args.Length < 2 || (args[0] != "check" && args[0] != "analyze"))
        {
            Console.Error.WriteLine("usage: modguard check <folder>... [--cache DIR] [--blocklist URL] [--no-av]\n" +
                                    "       modguard analyze <file>...");
            return 2;
        }
        var rest = args.Skip(1).ToList();
        if (args[0] == "analyze")
        {
            foreach (var f in rest)
            {
                SortedSet<string> caps;
                var findings = ModGuard.AnalyzeBytes(Path.GetFileName(f), File.ReadAllBytes(f), null, out caps);
                Console.WriteLine(JsonSerializer.Serialize(new
                {
                    file = f,
                    capabilities = caps,
                    rules = findings.Select(x => x.Rule).Distinct().OrderBy(x => x, StringComparer.Ordinal),
                }));
            }
            return 0;
        }

        var opts = new ModGuardOptions { Log = Console.WriteLine };
        var folders = new List<string>();
        for (int i = 0; i < rest.Count; i++)
        {
            if (rest[i] == "--cache") opts.CacheDirectory = rest[++i];
            else if (rest[i] == "--blocklist") opts.Blocklists.Add(rest[++i]);
            else if (rest[i] == "--no-av") opts.UseWindowsAntivirus = false;
            else folders.Add(rest[i]);
        }
        int worst = 0;
        using (var guard = new ModGuard(opts))
        {
            guard.Prepare();
            Console.WriteLine("antivirus: " + (guard.AntivirusAvailable ? "Windows AMSI" : "not available"));
            foreach (var folder in folders)
            {
                ulong id;
                ulong.TryParse(Path.GetFileName(folder.TrimEnd('/', '\\')), out id);
                var c = guard.CheckFolder(folder, id);
                worst = Math.Max(worst, (int)c.Verdict);
                foreach (var f in c.TopReasons(6)) Console.WriteLine("    " + f);
            }
        }
        return worst == (int)Verdict.Malicious ? 1 : 0;
    }
}
