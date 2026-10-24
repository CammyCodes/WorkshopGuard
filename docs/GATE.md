# The launch gate

The Docker service watches a game's whole Workshop. The launch gate guards one player's PC: it sits between Steam
and the game, so every mod you have installed is checked **before the game starts**, and nothing in a mod can run
first.

Most launches you won't notice it. If nothing changed since the last check, the game starts in about half a second,
with no window. If Steam has installed a new mod or an update, a small window shows while just the changed files are
scanned, then the game starts. If something looks dangerous, it stops and tells you why.

## Install (Windows)

You need Python 3.10 or newer from [python.org](https://www.python.org/downloads/). Then, in the WorkshopGuard folder:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install-gate.ps1            # PlateUp!
powershell -ExecutionPolicy Bypass -File scripts\install-gate.ps1 -Game 4000 # any game, by name or app ID
```

That sets up the scanners, downloads YARA Forge's rules, scans your mods once, and sets the game's Steam launch
options to:

```text
"<WorkshopGuard>\.gate\venv\Scripts\pythonw.exe" "<WorkshopGuard>\gate.pyw" %command%
```

If Steam is open it can't save launch options for you (Steam overwrites them when it closes), so the line goes on
your clipboard instead: right-click the game in Steam > Properties > Launch Options, and paste. Any game arguments
you used before go after `%command%`. Run the script again to update the rules; `-Uninstall` takes it out.

## What happens at each launch

1. **Hash everything.** Every file of every installed mod (every Steam library's Workshop folder, plus the game's
   own `Mods` folder for PlateUp) is SHA-256 hashed in full, every launch: about 40 ms for a typical PlateUp setup.
   Timestamps can be faked; hashes can't. The files the game will load are held open so nothing can change them
   between the check and the game reading them.
2. **Skip what's known.** A mod whose files are exactly as they were at its last clean check passes straight
   through. Results are cached per file, so an update that changes one DLL scans one DLL, and a library shipped in
   30 mods (0Harmony.dll) is scanned once.
3. **Scan what's new.** WorkshopGuard's own rules for Workshop malware, YARA Forge's ~5,000 community rules, the .NET
   mod analyzer, Windows program checks, per-game file checks and **Microsoft Defender**, plus known-bad hashes,
   blocklists, and optionally ClamAV, capa and VirusTotal/MetaDefender/MalwareBazaar hash lookups. Change a rule or
   update the rules and every mod is checked again with them.
4. **Decide.**
   - *Malicious*: moved to quarantine before the game starts, even if you choose Quit. Its files are remembered, so
     when Steam puts it back, or someone re-uploads the same payload under a new ID, it's stopped without a scan.
   - *Suspicious*: your call. Tick "I trust this version" to load it. Your answer is remembered until the mod
     changes.
   - *The game's own files changed without a Steam update*, or a DLL-hijack file (`winhttp.dll`, `version.dll`...)
     appeared next to the game: you can repair the game with Steam, trust the files, or quit.
5. **Start the game and check what it loaded.** For PlateUp the gate reads the game's log until it says which mod
   folders it loaded. If any wasn't checked, the game is closed straight away. Then the files are let go.
6. **Keep watch while you play** (low priority). If Steam downloads an update mid-session, it's scanned then and
   there, so the next launch is instant, or it's quarantined if it's malicious. The game's own files get a full
   re-hash in the background too.

If the gate itself fails, it says so and offers to quit (the safe choice) or start the game with mods turned off.

## Commands

From the WorkshopGuard folder, with `.gate\venv\Scripts\python -m workshopguard.gate <command>`:

| | |
|---|---|
| `scan [game]` | Check every mod now, without starting the game |
| `status [game]` | Every mod's verdict, what's in quarantine, recent launches and how long they took |
| `restore <id>` | Put a quarantined mod back and allow that exact version (if you're sure it's a false alarm) |
| `forget <id>` | Forget your answer about a mod, so you're asked again |
| `install` / `uninstall [game]` | Set or clear the Steam launch options |
| `guard [game]` | Stay running and check mods as Steam installs them, even when the game isn't running |

Settings go in `%LOCALAPPDATA%\WorkshopGuard\gate.json` (all optional). That folder also holds the gate's database, its
log (`gate.log`) and the quarantine.

```json
{
  "suspicious": "ask",
  "blocklists": ["http://127.0.0.1:8081/blocklist/{appid}.json"],
  "defender": true,
  "clamav": "",
  "malwarebazaar_key": "",
  "watch_while_playing": true,
  "verify_game_files": true
}
```

`suspicious` can be `ask`, `block` or `allow`. `blocklists` takes URLs or file paths in the format a WorkshopGuard
server publishes (`/blocklist/<appid>.json`), so a game community can share one. Online lookups send only file hashes.

## What it can't do

The same limits as WorkshopGuard itself: it reads mods without running them, so a brand-new trick no rule describes
can get past, and so can a mod that downloads its real payload later.

It guards launches that go through Steam: Play in your library, desktop shortcuts and `steam://` links. Running the
game's .exe directly skips it (PlateUp doesn't restart itself through Steam). Mods it has already quarantined stay
out either way. To cover direct launches too, keep `guard` running: it checks each new or updated mod as soon as
Steam has finished installing it, game running or not. To start it with Windows, put this in your Startup folder
(`shell:startup`) as a shortcut:

```text
"<WorkshopGuard>\.gate\venv\Scripts\pythonw.exe" "<WorkshopGuard>\gate.pyw" guard plateup
```
