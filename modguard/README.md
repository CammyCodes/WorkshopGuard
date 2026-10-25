<p align="center"><img src="../docs/plateup/banner.png" alt="WorkshopGuard for PlateUp!" width="100%"></p>

# ModGuard: WorkshopGuard inside the game

ModGuard is WorkshopGuard's mod checker as plain C#, for a Unity/C# game to call **before it loads each mod**. It
needs no other packages, no Python and no server. It's .NET Standard 2.0 with C# 7.3, so it builds in any Unity
from 2018.4 on (Mono or IL2CPP). It never loads or runs a mod's code to check it: it reads the bytes.

It's written with PlateUp! in mind, and the glue for PlateUp!'s mod loader is ready to paste in: about six lines.
It works the same for any Unity game that loads mod DLLs.

> Unofficial and community-made. Not made by or affiliated with It's Happening or Yogscast Games.

## What it checks

For every file in a mod folder, every launch:

1. **SHA-256 hash.** Results are cached per file hash, so on later launches an unchanged mod costs only hashing:
   about 0.4 s for nine typical PlateUp! mods in the game's own Mono runtime.
2. **Known-bad files.** Files that made an earlier mod malicious. A re-download, or the same payload re-uploaded
   under a new Workshop ID, is refused without being analysed again.
3. **Blocklists** (optional): banned Workshop item IDs and file hashes from a WorkshopGuard server
   ([format](../docs/FOR_GAME_DEVELOPERS.md#stop-your-game-loading-banned-mods)), fetched in the background with the
   last copy kept for offline play.
4. **.NET code analysis** of each DLL, read straight from its metadata. It looks at which framework methods it calls
   (Process.Start, WebClient, Assembly.Load(byte[]), ProtectedData.Unprotect, Steam Workshop upload, Steam friend
   messages...), its native imports, its string literals (Discord webhooks, Steam's `ssfn` and `loginusers.vdf`,
   browser `Login Data`, `powershell -enc`...), obfuscators and embedded programs. Then it checks the combinations
   real Workshop malware needs: download + run, read secrets + send, download + load as code, republish to the
   Workshop.
5. **File checks**: programs disguised as images, double extensions (`readme.txt.bat`), scripts and executables a
   mod never needs, native DLLs, packers, and everything inside zips.
6. **The player's own antivirus** through Windows AMSI (Microsoft Defender and most others). A file the antivirus
   refuses to let anyone open counts as malicious, not just "unreadable".

Steps 4 and 5 are a rule-for-rule port of WorkshopGuard's Python engine, and they give the same answers. Checked on
583 real programs (all of PlateUp!'s own DLLs, the nine PlateUp! mods on our test PC, the .NET runtime, Steam's and Python's
DLLs): identical capabilities and findings on every one (`tests/parity.py`).

**Verdicts:** any critical finding is *malicious* and refused. A high finding, or three different medium findings in
one file, is *suspicious*: loaded but reported (or refused with `BlockSuspicious = true`). Otherwise it's *clean*.
Low and info findings never change a verdict, because big framework mods (Harmony, KitchenLib) have lots of them.
All nine PlateUp! mods on our test PC come out clean.

## Adding it to PlateUp!

1. Put `src/*.cs` and [`samples/PlateUp/ModSafetyCheck.cs`](samples/PlateUp/ModSafetyCheck.cs) in the
   KitchenMods assembly (or build `ModGuard.csproj` and reference `WorkshopGuard.ModGuard.dll`).
2. In `SteamWorkshopModSource.LoadMods()`, next to the existing `.bat` check (`item` is the
   `SteamUGC.SubscribedItem` being loaded, `name` the mod's name):

   ```csharp
   Mod refused = ModSafetyCheck.Refuse(item.Directory, item.Id.Value, name, this);
   if (refused != null)
   {
       list.Add(refused);
       continue;
   }
   ```

3. In `FolderModSource.LoadMods()`, before `LoadModFromFolder` (`folder` is the mod's folder, `folderName` its name):

   ```csharp
   Mod refused = ModSafetyCheck.Refuse(folder, 0uL, folderName, this);
   if (refused != null) { list.Add(refused); continue; }
   ```

4. At the end of `ModPreload.LoadMods()`: `ModSafetyCheck.Finish();` (saves results for next launch).

A refused mod is added as `ModState.FailedDuringLoad` with no packs, the same way the loader already refuses a pinned
mod with a bad signature, so it shows up as a failed mod and none of its code is ever loaded.
`ModSafetyCheck.Refused` lists the refused mods with reasons a player can read, for a message on the main menu.

**Before start-up:** `ModSafetyCheck` has a `[RuntimeInitializeOnLoadMethod(BeforeSceneLoad)]` hook that loads the
cache and starts fetching blocklists before the first scene, so the checks in `LoadMods` never wait on the network.
`-nomods` skips it.

**Optional, closes the last gap:** in `AssemblyModPack.TryLoadFile` and `AssetBundleModPack.TryLoadFile`, read the
file with `ModSafetyCheck.ReadChecked(path)` instead of `File.ReadAllBytes(path)`. That returns the bytes only if
they're exactly what was checked, so nothing can swap a file between the check and the load.

**Blocklist:** add your own WorkshopGuard server's feed, e.g.
`ModSafetyCheck.Blocklists.Add("https://your-cdn/blocklist/1599600.json")`. With that in place, the blanket
"item ID above 3820868888" cut-off could go, and new mods could load again.

Ship ModGuard inside the game's own code, not as a Workshop mod. It contains its own rule text ("Login Data",
"Invoke-Expression"...) and fetches blocklists over HTTPS, so as a mod it would rightly look like the thing it hunts.

## Using it in any game

```csharp
using WorkshopGuard;

var guard = new ModGuard(new ModGuardOptions
{
    CacheDirectory = Path.Combine(Application.persistentDataPath, "WorkshopGuard"),
    Blocklists = { "https://your-cdn/blocklist/<appid>.json" },   // optional
    UseWindowsAntivirus = true,
    BlockSuspicious = false,
    Profile = GameProfile.UnityCSharp("My Game"),                 // what a normal mod contains
    Log = Debug.Log,
});
guard.Prepare();                                   // early: cache + blocklists in the background
ModCheck check = guard.CheckFolder(modFolder, workshopItemId);
if (!check.Allowed) Debug.LogError("Not loading " + modFolder + ": " + check.Summary());
guard.Save();                                      // after loading mods
```

`ModCheck` has the `Verdict`, `Findings` (each with a plain-English `Description`, the `File` and `Evidence`),
`TopReasons()`, every file's `Sha256`, and how long it took.

## Building and testing

```bash
dotnet build modguard/ModGuard.csproj -c Release           # WorkshopGuard.ModGuard.dll
dotnet test  modguard/tests/ModGuard.Tests                 # unit tests (some need Windows or the fake stealer fixture)
dotnet run --project modguard/tools/ModGuardCli -- check <mod folder>...
```

- `tests/parity.py` compares ModGuard with the Python engine on any folder of programs.
- `samples/PlateUp/PlateUpSample.csproj` and `tests/InGame/` build against a PlateUp! install
  (`-p:PlateUpManaged=...\PlateUp_Data\Managed`). The second is a throwaway mod that runs ModGuard and the PlateUp!
  hook inside the real game and logs to `Player.log`. That's how this was checked on build 26000811: all nine
  installed mods clean, the fake stealer refused as `FailedDuringLoad`, the antivirus reachable from the game's
  Mono runtime, and HTTPS blocklists working.

## Limits

It reads mods without running them, so a brand-new trick no rule describes can get past it, and so can a mod that
downloads its real payload later (it flags the download-then-load pattern that needs). It doesn't include YARA,
ClamAV or online scanners: the player's antivirus stands in for those, and a WorkshopGuard server can run all of them
and feed the blocklist. AMSI is Windows 10 and later only; elsewhere ModGuard runs its own checks.

MIT licence. Made by CammyCodes.
