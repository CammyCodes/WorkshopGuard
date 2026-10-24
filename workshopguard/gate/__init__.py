"""The launch gate: WorkshopGuard on the player's own PC, between Steam and the game.

Steam runs it in place of the game (launch options: `"...pythonw.exe" "...gate.pyw" %command%`), so it runs before
any mod code can:

  1. Hash every file of every installed mod (Workshop items in every Steam library, plus the game's local Mods
     folder) and the game's own code files, holding the files the game loads open read-only so nothing can swap
     them between the check and the game reading them.
  2. Anything unchanged since its last clean scan passes straight through, in milliseconds, with no window.
  3. New and changed mods are scanned (only their changed files: results are cached per file) with WorkshopGuard's
     engines plus Microsoft Defender, and checked against known-bad hashes and any blocklists.
  4. Dangerous mods are moved to quarantine before the game starts; suspicious ones are the player's call.
  5. The game starts. For PlateUp it reads the game's own log to confirm it loaded only checked mods, then lets go
     of the files and waits quietly, pre-scanning any update Steam downloads mid-session.
"""
