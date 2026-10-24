// WorkshopGuard ModGuard: check mods before a Unity/C# game loads them. MIT licence, github.com/CammyCodes/WorkshopGuard
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace WorkshopGuard
{
    public enum Severity { Info = 0, Low = 1, Medium = 3, High = 8, Critical = 50 }

    public enum Verdict { Clean, Suspicious, Malicious }

    /// <summary>One reason a mod looks the way it does, in words a player can read.</summary>
    public sealed class Finding
    {
        public string Engine;        // files | pe | dotnet | antivirus | blocklist | known-bad
        public Severity Severity;
        public string Rule;          // short id, e.g. dotnet.combo.stealer
        public string Description;
        public string File;          // path inside the mod folder
        public List<string> Evidence = new List<string>();

        public Finding(string engine, Severity severity, string rule, string description, string file,
                       IEnumerable<string> evidence = null)
        {
            Engine = engine;
            Severity = severity;
            Rule = rule;
            Description = description;
            File = file ?? "";
            if (evidence != null) Evidence.AddRange(evidence);
        }

        public Finding WithFile(string file)
        {
            return new Finding(Engine, Severity, Rule, Description, file, Evidence);
        }

        public override string ToString()
        {
            return Severity + ": " + Description + (File.Length > 0 ? " (" + File + ")" : "");
        }
    }

    /// <summary>The result of checking one mod folder.</summary>
    public sealed class ModCheck
    {
        public string Folder;
        public ulong ItemId;
        public Verdict Verdict;
        public int Score;
        public bool Allowed;                     // what the game should do: load it or not
        public List<Finding> Findings = new List<Finding>();
        public Dictionary<string, string> Sha256 = new Dictionary<string, string>();  // relative path -> hash
        public int FilesScanned;                 // files the engines actually read this time
        public int FilesFromCache;               // files already known from an earlier check
        public double Milliseconds;

        /// <summary>The most serious reasons, one line each: for a log line or a message to the player.</summary>
        public IEnumerable<Finding> TopReasons(int max = 4)
        {
            var seen = new HashSet<string>();
            return Findings.Where(f => f.Severity >= Severity.Medium)
                           .OrderByDescending(f => f.Severity)
                           .Where(f => seen.Add(f.Rule + "|" + f.File))
                           .Take(max);
        }

        public string Summary()
        {
            var sb = new StringBuilder();
            sb.Append(Verdict.ToString().ToLowerInvariant());
            foreach (var f in TopReasons()) sb.Append("; ").Append(f.Description).Append(f.File.Length > 0 ? " (" + f.File + ")" : "");
            return sb.ToString();
        }
    }

    internal static class Verdicts
    {
        /// <summary>Same rule as WorkshopGuard's server: any critical finding = malicious; any high finding, or one
        /// file with three different medium findings = suspicious. Low/info never change the verdict (big framework
        /// mods like Harmony have lots of them).</summary>
        public static Verdict For(IList<Finding> findings, out int score)
        {
            score = findings.Sum(f => (int)f.Severity);
            if (findings.Any(f => f.Severity == Severity.Critical)) return Verdict.Malicious;
            if (findings.Any(f => f.Severity == Severity.High)) return Verdict.Suspicious;
            var mediums = findings.Where(f => f.Severity == Severity.Medium)
                                  .GroupBy(f => f.File)
                                  .Any(g => g.Select(f => f.Rule).Distinct().Count() >= 3);
            return mediums ? Verdict.Suspicious : Verdict.Clean;
        }
    }
}
