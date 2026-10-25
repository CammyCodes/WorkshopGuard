# Changelog

## Unreleased

## 1.0.0 (2026-10-25)

The first release: everything needed to watch a game's Workshop, guard your own launches, and let a game check mods
itself.

**Scanner (Docker)**
- Watches any game's Workshop for new items and updates, downloads them with SteamCMD (anonymous where the game
  allows it, a cached login otherwise) and scans them in a locked-down container. Files are only read, never run.
- Seven local engines (ClamAV, WorkshopGuard's own rules, YARA Forge, Mandiant capa, .NET mod analysis, Windows
  program checks, per-game file checks) and three online ones with free keys (VirusTotal, MetaDefender,
  MalwareBazaar). The image rebuilds weekly with fresh community rules.
- Alerts to Discord or any webhook, a local dashboard, `deep-scan` for every engine on one mod, and protect mode,
  which quarantines malicious mods from your own Steam folder as they install.
- A self-test that plants a harmless fake detection and checks every step, alert included.

**Publisher mode (game developers)**
- Ban and unban items and uploaders on your own game's Workshop with a Steamworks publisher key. Never deletes
  anything. Auto-ban is off by default.
- A blocklist feed (banned item IDs and the hashes of their flagged files) for your game to check before loading
  mods.

**Launch gate (Windows)**
- Runs between Steam and the game: hashes every mod each launch, scans only what changed (Microsoft Defender
  included), and quarantines dangerous mods before the game starts. Unchanged mods start in about half a second.
- For PlateUp!: holds the files until the game has loaded them, and checks its log to confirm it loaded only checked
  mods.
- Themes, so a game can ship the gate under its own look. PlateUp! Mod Check is the example.

**ModGuard (C#)**
- The same mod checks as a dependency-free .NET Standard 2.0 library for a game's own mod loader, on NuGet as
  `WorkshopGuard.ModGuard`. Gives identical findings to the Python engine on 583 real programs.
- Ready-to-paste glue for PlateUp!'s mod loader.
