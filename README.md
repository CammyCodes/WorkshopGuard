# WorkshopGuard

Malware scanning for the Steam Workshop that anyone can run. Pick your game, start it with Docker, and it checks
every new upload and every update to existing items, then tells you (Discord, webhook, dashboard) when something looks
dangerous.

Steam Workshop malware isn't hypothetical any more. In 2026 alone: People Playground was hit twice (a self-spreading
mod that republished itself from victims' accounts), PlateUp! had a mod that turned malicious the day after upload,
and Project Zomboid banned 14 mods hiding obfuscated code. Valve doesn't scan mod code, so the communities that care
about a game have to watch it themselves. WorkshopGuard makes that a five-minute job.

## What it does

```
 Steam Workshop ──► new uploads + updates ──► SteamCMD download ──► scanners ──► verdict ──► Discord / webhook
   (any game)        (checked every 15 min)     (in Docker)          │            clean       dashboard
                                                                     │            suspicious  quarantine
                                                                     ▼            malicious
                       ClamAV · YARA rules for Workshop malware · .NET mod analysis · PE imports · file checks
```

- **Watches** a game's Workshop for new items and updates (an update that turns a good mod bad is the usual trick),
  and can scan everything already there once.
- **Downloads** items with SteamCMD, anonymously where the game allows it, otherwise with an account you log in once.
- **Scans** every file, including inside zip archives:
  - **ClamAV** antivirus signatures, kept up to date automatically.
  - **YARA rules for Workshop malware**: Steam session theft (`ssfn`, `loginusers.vdf`), Discord token grabbers,
    browser password stealers, webhook exfiltration, PowerShell/batch droppers, persistence, wipers, Lua and C#
    backdoors, mods that republish themselves to the Workshop or message your friends.
  - **.NET mod analysis** (PlateUp, RimWorld, Cities: Skylines and other Unity/C# games): reads what the mod's
    code calls without running it. Single capabilities are normal (KitchenLib talks to the internet, Harmony patches
    code); it's the combinations malware needs that raise the alarm, like *download + load as code* or *read Steam
    login files + send them out*.
  - **Windows executables**: dangerous imports, packers.
  - **File checks** per game: an `.exe`, `.bat` or DLL in a Black Ops III map, a program hiding under a `.png`
    name, password-protected archives.
  - **VirusTotal** hash lookups (optional; only hashes are sent).
  - **Copycats**: an item with the same title as an older item by a different uploader.
- **Reports**: `clean`, `suspicious` (worth a human look) or `malicious` (strong evidence), with plain-English
  reasons, sent to Discord or any webhook and shown on a local dashboard. Flagged files are kept in quarantine.

Downloaded files are **never run**. They're read as data inside a locked-down container (read-only filesystem, no
Linux capabilities, no privilege escalation).

## Quick start

You need Docker on a machine that's always on: a VPS, a home server, a NAS, or your own PC. It needs an x86-64 CPU
(SteamCMD has no ARM build), about 2 GB of RAM with ClamAV (300 MB without), and disk space for the biggest item you
want to scan.

```bash
git clone https://github.com/CammyCodes/WorkshopGuard.git
cd WorkshopGuard
cp .env.example .env
```

Open `.env` and set the game. That's the only required setting:

```ini
GAMES=plateup          # or an app ID: GAMES=1599600 — several: GAMES=plateup,bo3
DISCORD_WEBHOOK_URL=   # optional: where alerts go
```

The app ID is the number in the game's store URL (`store.steampowered.com/app/1599600/...`). Any game with a Workshop
works; [known games](#games) get tuned file checks.

```bash
docker compose up -d
```

Open <http://localhost:8080> for the dashboard. The first check runs straight away.

### Games that need a Steam account

Some games (Black Ops III, many others) let anyone download their Workshop items. Others (PlateUp! for one) only give
them to an account that owns the game, and WorkshopGuard will tell you so in the dashboard. For those:

1. Set `STEAM_USERNAME=` in `.env` to an account that owns the game. A spare account is best.
2. Log in once (SteamCMD asks for the password and Steam Guard code; only Steam's login token is kept):
   ```bash
   docker compose run --rm guard login
   ```
   On Windows, `.\scripts\steam-login.ps1` does steps 1 and 2 for you. With the Steam Mobile authenticator, approve
   the login on your phone when SteamCMD says "Waiting for confirmation".
3. `docker compose up -d` again. Items that failed are retried straight away.

### Check it works (fake detection)

```bash
docker compose run --rm guard selftest bo3
```

This downloads a real item, plants two harmless test files in it (the standard EICAR antivirus test file and a
WorkshopGuard test marker), scans it, records it and sends a `[TEST]` alert to your webhook. Every step prints
PASS/FAIL.

## Commands

All commands run as `docker compose run --rm guard <command>`.

| Command | What it does |
|---|---|
| `watch` | The default: watch, scan and alert forever |
| `selftest [game]` | Fake detection end to end, including the alert |
| `scan-item <game> <id> [<id>...]` | Scan specific items now (`--inject-test` plants the fake detection) |
| `scan-path <game> <folder>` | Scan items already on disk, e.g. your own `steamapps/workshop/content/<appid>` |
| `login` | Log SteamCMD in once for games that need an account |
| `list <game>` | Show the newest items (`--sort lastupdated`, `--pages N`) |
| `status` | Counts and the latest flagged items |
| `rescan --all` | Scan everything again, e.g. after adding rules |

Scan the mods you already have installed (mount the folder read-only):

```bash
docker compose run --rm -v "C:/Program Files (x86)/Steam/steamapps/workshop/content/1599600:/scan:ro" guard scan-path plateup /scan
```

## Settings

All in `.env` (see `.env.example` for the full list):

| Setting | Default | |
|---|---|---|
| `GAMES` | `plateup` | Comma-separated app IDs or names |
| `BACKFILL` | `none` | On first start, scan `none`, `all`, or the N most recently updated existing items |
| `POLL_MINUTES` | `15` | How often to check for new uploads and updates |
| `MAX_ITEM_MB` | `2048` | Skip bigger items (some maps are over 10 GB) |
| `STEAM_USERNAME` | | Account for games that block anonymous downloads |
| `DISCORD_WEBHOOK_URL` | | Discord alerts |
| `WEBHOOK_URL` | | JSON alerts to anything else (Slack-compatible `text` field included) |
| `NOTIFY_ON` | `malicious,suspicious` | Which verdicts alert |
| `PUBLIC_URL` | | Your dashboard's address, for links in alerts |
| `VIRUSTOTAL_API_KEY` | | Hash lookups for executables |
| `QUARANTINE_FLAGGED` | `true` | Keep flagged items in the data volume for review |

**Your own rules:** drop `.yar` files into `custom-rules/`. Give each a `severity` (`info` to `critical`) and a
`description` in its `meta`; a `critical` match makes the item `malicious`.

**Dashboard access:** it listens on `127.0.0.1:8080` only. To reach it from elsewhere, put it behind a reverse proxy
with authentication, or use an SSH tunnel (`ssh -L 8080:localhost:8080 your-vps`).

## Games

Any app ID works with generic checks. These have tuned profiles (what a normal item contains):

| Game | Name | App ID | Anonymous download |
|---|---|---|---|
| PlateUp! | `plateup` | 1599600 | No, needs an owning account |
| Call of Duty: Black Ops III | `bo3` | 311210 | Yes |
| People Playground | `peopleplayground` | 1118200 | |
| Project Zomboid | `zomboid` | 108600 | |
| Garry's Mod | `gmod` | 4000 | |
| RimWorld | `rimworld` | 294100 | |
| Tabletop Simulator | `tts` | 286160 | |
| Cities: Skylines | `cities` | 255710 | |
| Wallpaper Engine | `wallpaperengine` | 431960 | |

Adding a game is a few lines in [`workshopguard/games.py`](workshopguard/games.py).

## Reading a verdict

- **malicious**: strong evidence, like a known antivirus signature, a download-and-run pattern, code that reads
  Steam/Discord/browser secrets and can send them out, or a program disguised as an image. Unsubscribe and report the
  item to Valve from its Workshop page.
- **suspicious**: something a normal item for this game wouldn't have. Look at the reasons; it may be fine (an
  update checker, a bundled tool) or it may be the start of something.
- **clean**: nothing found. Not a guarantee: obfuscated or brand-new techniques can get past any scanner.

A flag is a reason to look closer, not proof. Please check before accusing a mod author publicly.

## How it works

- **Listing** reads the public Workshop browse pages (no API key needed), newest first and most recently updated
  first, and remembers each item's `time_updated` so updates get rescanned.
- **Details** come from Steam's keyless `GetPublishedFileDetails` API, including Steam's own ban flag.
- **Downloads** go through SteamCMD inside the container. SteamCMD and its login token live in the `guard-data` volume.
- **State** is a SQLite database in the same volume. JSON API: `/api/items?verdict=malicious`, `/api/stats`.

## Development

```bash
sh tests/build_fixtures.sh   # builds an inert fake "stealer" mod + a fake booby-trapped BO3 map
docker compose run --rm --entrypoint python -v ./tests:/app/tests:ro guard -m pytest -q /app/tests
docker compose run --rm -v ./tests/fixtures/out:/fx:ro guard scan-path plateup /fx/plateup --offline
```

`docker-compose.test.yml` adds a local webhook receiver so you can watch alerts arrive without Discord:

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml up -d
docker compose -f docker-compose.yml -f docker-compose.test.yml logs -f sink
```

The test fixtures are not malware: they reference the same APIs real Workshop malware uses, but nothing in them is
ever called and every address points at the reserved `.invalid` domain.

## Licence

MIT. Made by CammyCodes.
