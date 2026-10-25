# WorkshopGuard.ModGuard

Checks mods **before a Unity/C# game loads them**, by reading their bytes, never running them. It's WorkshopGuard's
mod checker as plain C#: .NET Standard 2.0, C# 7.3, no dependencies, so it builds in any Unity from 2018.4 on (Mono or
IL2CPP).

For every file in a mod folder it checks:

- its **SHA-256** against known-bad files and optional WorkshopGuard blocklists (cached for offline play),
- the **.NET code** inside, for the combinations Workshop malware needs: download + run, read Steam/Discord/browser
  secrets + send, download + load as code, republish to the Workshop,
- **files that don't belong** in a mod: programs disguised as images, double extensions, scripts, packers, zips,
- the **player's own antivirus** through Windows AMSI.

Results are cached per file hash, so unchanged mods cost only hashing on later launches (about 0.4 s for nine
typical PlateUp! mods).

```csharp
using WorkshopGuard;

var guard = new ModGuard(new ModGuardOptions
{
    CacheDirectory = Path.Combine(Application.persistentDataPath, "WorkshopGuard"),
    Blocklists = { "https://your-cdn/blocklist/<appid>.json" },   // optional
    UseWindowsAntivirus = true,
    Profile = GameProfile.UnityCSharp("My Game"),
    Log = Debug.Log,
});
guard.Prepare();                                   // early: cache + blocklists in the background
ModCheck check = guard.CheckFolder(modFolder, workshopItemId);
if (!check.Allowed) Debug.LogError("Not loading " + modFolder + ": " + check.Summary());
guard.Save();                                      // after loading mods
```

**Using Unity?** Unity doesn't read NuGet packages directly: download `WorkshopGuard.ModGuard.dll` from the
[GitHub release](https://github.com/CammyCodes/WorkshopGuard/releases/latest) into `Assets/Plugins`, or copy the
source files in.

No scanner catches everything. A brand-new trick, or a mod that downloads its real payload later, can get past it.
Treat "clean" as "nothing found", not "guaranteed safe".

Full guide, the PlateUp! integration and how it was tested:
[github.com/CammyCodes/WorkshopGuard/tree/main/modguard](https://github.com/CammyCodes/WorkshopGuard/tree/main/modguard).
MIT licence. Made by CammyCodes.
