using System;
using System.IO;
using System.Linq;
using KitchenMods;
using UnityEngine;
using WorkshopGuard;

// Runs ModGuard over every installed mod from inside the game and logs what it finds, so we know it works on the
// game's own runtime before anyone wires it into the loader. Output: lines starting "[WorkshopGuard]" in Player.log.
public class ModGuardInGameTest : IModInitializer
{
    public void PostActivate(Mod mod)
    {
        var total = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            string game = Path.GetFullPath(Path.Combine(Application.dataPath, ".."));
            string workshop = Path.GetFullPath(Path.Combine(game, "..", "..", "..", "workshop", "content", "1599600"));
            var options = new ModGuardOptions
            {
                CacheDirectory = Path.Combine(Application.persistentDataPath, "WorkshopGuard-test"),
                Log = Debug.Log,
                // any HTTPS JSON proves the game's runtime can fetch a blocklist; this one simply lists no items
                Blocklists = { "https://api.github.com/repos/CammyCodes/WorkshopGuard" },
            };
            using (var guard = new ModGuard(options))
            {
                guard.Prepare();
                Debug.Log("[WorkshopGuard] in-game test: runtime " + Environment.Version + ", antivirus " +
                          (guard.AntivirusAvailable ? "Windows AMSI" : "not available"));
                var folders = Directory.Exists(workshop) ? Directory.GetDirectories(workshop).ToList() : new System.Collections.Generic.List<string>();
                foreach (var f in folders)
                {
                    ulong id;
                    ulong.TryParse(Path.GetFileName(f), out id);
                    guard.CheckFolder(f, id);
                }
                string mods = Path.Combine(game, "Mods");
                foreach (var f in Directory.GetDirectories(mods)) guard.CheckFolder(f);
                var first = guard.Results.FirstOrDefault(r => r.Sha256.Keys.Any(k => k.EndsWith(".dll")));
                if (first != null)
                {
                    var dll = Path.Combine(first.Folder, first.Sha256.Keys.First(k => k.EndsWith(".dll")));
                    Debug.Log("[WorkshopGuard] in-game test: ReadChecked " + Path.GetFileName(dll) + " = " + guard.ReadChecked(dll).Length + " bytes");
                }
                // the PlateUp! hook itself: a clean mod passes, the fake stealer becomes a FailedDuringLoad mod
                var stealer = Environment.GetEnvironmentVariable("WG_TEST_STEALER");
                if (folders.Count > 0)
                    Debug.Log("[WorkshopGuard] in-game test: Refuse(" + Path.GetFileName(folders[0]) + ") = " +
                              (KitchenMods.ModSafetyCheck.Refuse(folders[0], 1, "clean mod", null) == null ? "null (loads)" : "REFUSED"));
                if (!string.IsNullOrEmpty(stealer) && File.Exists(stealer))
                {
                    var bad = Path.Combine(Application.persistentDataPath, "WorkshopGuard-test", "9000000001");
                    Directory.CreateDirectory(bad);
                    File.Copy(stealer, Path.Combine(bad, "FakeStealerMod.dll"), true);
                    var m = KitchenMods.ModSafetyCheck.Refuse(bad, 9000000001, "Fake stealer", null);
                    Debug.Log("[WorkshopGuard] in-game test: Refuse(fake stealer) = " + (m == null ? "null (LOADED!)" : m.Name + " " + m.State) +
                              "; refused this launch: " + KitchenMods.ModSafetyCheck.Refused.Count);
                    Directory.Delete(bad, true);
                }
                KitchenMods.ModSafetyCheck.Finish();
                var r2 = guard.Results;
                Debug.Log("[WorkshopGuard] in-game test: done, " + r2.Count + " mods (" +
                          string.Join(", ", r2.GroupBy(r => r.Verdict).Select(g => g.Count() + " " + g.Key)) + ") in " +
                          total.ElapsedMilliseconds + " ms");
            }
        }
        catch (Exception e)
        {
            Debug.LogError("[WorkshopGuard] in-game test FAILED: " + e);
        }
    }

    public void PreInject() { }
    public void PostInject() { }
}
