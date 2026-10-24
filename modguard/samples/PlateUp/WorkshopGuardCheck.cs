// WorkshopGuard for PlateUp!: the glue between ModGuard and KitchenMods. Add this file and ModGuard's src/*.cs (or
// WorkshopGuard.ModGuard.dll) to the KitchenMods assembly, then add the calls shown in modguard/README.md:
//   SteamWorkshopModSource.LoadMods  next to the existing .bat check (item = the SubscribedItem being loaded):
//       var refused = WorkshopGuardCheck.Refuse(item.Directory, item.Id.Value, name, this);
//       if (refused != null) { list.Add(refused); continue; }
//   FolderModSource.LoadMods         the same, with (folder, 0, folderName, this)
//   ModPreload.LoadMods              after the sources have run: WorkshopGuardCheck.Finish();
// MIT licence, github.com/CammyCodes/WorkshopGuard. Unofficial; not made by It's Happening.
using System.Collections.Generic;
using System.IO;
using System.Linq;
using UnityEngine;
using WorkshopGuard;

namespace KitchenMods
{
    public static class WorkshopGuardCheck
    {
        /// <summary>Blocklists to check (WorkshopGuard's format). Host your own WorkshopGuard server's
        /// /blocklist/1599600.json behind HTTPS, or leave it empty to rely on ModGuard's own checks.</summary>
        public static readonly List<string> Blocklists = new List<string>();

        static ModGuard guard;
        static readonly List<ModCheck> refused = new List<ModCheck>();

        public static ModGuard Guard
        {
            get
            {
                if (guard == null)
                {
                    guard = new ModGuard(new ModGuardOptions
                    {
                        CacheDirectory = Path.Combine(Application.persistentDataPath, "WorkshopGuard"),
                        Blocklists = Blocklists,
                        UseWindowsAntivirus = true,
                        BlockSuspicious = false,
                        Log = Debug.Log,
                    });
                }
                return guard;
            }
        }

        /// <summary>Before the first scene loads: read remembered results and start fetching blocklists, so the checks
        /// in LoadMods don't wait on the network.</summary>
        [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.BeforeSceneLoad)]
        static void Boot()
        {
            if (!ModsDisabled()) Guard.Prepare();
        }

        static bool ModsDisabled()
        {
            return System.Environment.GetCommandLineArgs().Contains("-nomods");
        }

        /// <summary>Checks a mod folder. Returns null if it may load; otherwise a Mod already marked FailedDuringLoad
        /// (like a pinned mod with a bad signature) to add to the list instead, so it shows up as a failed mod.</summary>
        public static Mod Refuse(string folder, ulong id, string name, ModSource source)
        {
            ModCheck check = Guard.CheckFolder(folder, id);
            if (check.Allowed)
            {
                if (check.Verdict == Verdict.Suspicious)
                    Debug.LogWarning("[WorkshopGuard] loading " + name + " but it looks unusual: " + check.Summary());
                return null;
            }
            Debug.LogError("[WorkshopGuard] refusing to load " + name + " (" + id + "): " + check.Summary());
            lock (refused) refused.Add(check);
            var mod = new Mod(id, name);
            mod.State = ModState.FailedDuringLoad;
            mod.Source = source;
            return mod;
        }

        /// <summary>The mods refused this launch, with reasons a player can read (for a message on the main menu).</summary>
        public static IList<ModCheck> Refused
        {
            get { lock (refused) return refused.ToList(); }
        }

        /// <summary>After loading mods: remember results so the next launch only checks what changed.</summary>
        public static void Finish()
        {
            if (guard != null) guard.Save();
        }

        /// <summary>Optional, in AssemblyModPack/AssetBundleModPack.TryLoadFile instead of File.ReadAllBytes: the bytes
        /// exactly as they were checked, or an exception if the file changed after the check.</summary>
        public static byte[] ReadChecked(string path)
        {
            return Guard.ReadChecked(path);
        }
    }
}
