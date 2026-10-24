# WorkshopGuard for game developers

Run WorkshopGuard on your own game and it can take bad items off your Workshop for everyone, and tell your game
which mods to refuse to load.

## Set up

1. In Steamworks, get a **publisher Web API key**: partner.steamgames.com > Users & Permissions > Manage Groups >
   pick a group that has your app > create a Web API key.
2. In `.env`:
   ```ini
   GAMES=1599600              # your game
   PUBLISHER_KEY=...          # the publisher key (keep it secret: it can ban items)
   PUBLISHER_APPS=1599600     # the apps it may moderate; WorkshopGuard never acts on any other
   ADMIN_PASSWORD=...         # protects the dashboard and its Ban buttons
   AUTO_BAN=off               # see below
   ```
3. `docker compose up -d`. The dashboard (<http://localhost:8080>) now has a **Review queue**, Ban buttons on
   each flagged item, and a **Moderation log**.

## Banning

| You do | Steam call | Effect |
|---|---|---|
| **Ban this item for everyone** | `IPublishedFileService/UpdateBanStatus` | The item is hidden on your Workshop. The reason (WorkshopGuard's findings) is visible to admins only. Reversible. |
| **Unban** | the same, `banned=false` | Back on the Workshop, and marked "cleared" so it won't be auto-banned again. |
| **Ban the uploader** | `IPublishedFileService/UpdateAppUGCBan` | They can't post Workshop items for your game (for `UPLOADER_BAN_DAYS`, 0 = permanent). They see `UPLOADER_BAN_REASON`. |
| **Mark as a false alarm** | none | Leaves the review queue and the blocklist. |

From the command line: `ban`, `unban`, `ban-uploader`, `unban-uploader` (`docker compose run --rm guard ban <game>
<item id> --reason "..."`). Every action is logged and posted to your alert channel.

WorkshopGuard never **deletes** items. A ban keeps the evidence and can be undone; a scanner can be wrong.

### Auto-ban

| `AUTO_BAN` | Bans automatically when |
|---|---|
| `off` (default) | never: a person reviews and clicks Ban |
| `confirmed` | a known-malware engine agrees: ClamAV, VirusTotal (3+ engines), MetaDefender (3+), MalwareBazaar, or a high-confidence YARA Forge rule. WorkshopGuard's own heuristics alone never auto-ban. |
| `malicious` | any malicious verdict, heuristics included |

Start with `off`, watch what it flags for a while, then consider `confirmed`. `BAN_UPLOADER=true` also bans the
uploader on an auto-ban. Self-tests and planted test files are never banned.

## Stop your game loading banned mods

A Workshop ban hides the item, but players who already downloaded it may still have it, and PlateUp! had to patch the
game for exactly that in October 2026. So WorkshopGuard publishes a **blocklist** your game can check before loading
mods:

```
GET http://<your server>:8081/blocklist/<appid>.json
```

```json
{
  "appid": 1599600,
  "generated": 1792880000,
  "items": [{"id": "3820000000", "title": "...", "creator": "7656...", "banned_at": 1792870000,
             "reason": "...", "sha256": ["9f2c..."]}],
  "sha256": ["9f2c..."]
}
```

`items` are the mods you banned. `sha256` are the hashes of their **flagged** files, so a re-upload of the same
payload under a new item ID is caught too. A file that also ships in a clean mod (say `0Harmony.dll`) is never
listed, so blocking one bad mod can't break good ones.

Port 8081 serves only this file. It listens on localhost unless you set `BLOCKLIST_BIND=0.0.0.0`. Better: put it
behind HTTPS (your CDN or a reverse proxy) and point the game at that.

### Checking it in a Unity game

```csharp
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using UnityEngine;
using UnityEngine.Networking;

// Before loading Workshop mods: fetch the blocklist (falling back to the last copy when offline) and skip any
// mod whose item ID, or any of whose DLLs, is on it.
public static class WorkshopBlocklist
{
    const string Url = "https://your-cdn.example/blocklist/1599600.json";
    static string CachePath => Path.Combine(Application.persistentDataPath, "workshop-blocklist.json");

    [Serializable] class Entry { public string id; }
    [Serializable] class List { public Entry[] items = new Entry[0]; public string[] sha256 = new string[0]; }

    static HashSet<string> ids = new HashSet<string>(), hashes = new HashSet<string>();

    public static IEnumerator Fetch()
    {
        string json = null;
        using (var req = UnityWebRequest.Get(Url))
        {
            req.timeout = 5;
            yield return req.SendWebRequest();
            if (req.result == UnityWebRequest.Result.Success)
            {
                json = req.downloadHandler.text;
                File.WriteAllText(CachePath, json);
            }
        }
        if (json == null && File.Exists(CachePath)) json = File.ReadAllText(CachePath);
        var list = json == null ? new List() : JsonUtility.FromJson<List>(json);
        ids = new HashSet<string>(list.items.Select(i => i.id));
        hashes = new HashSet<string>(list.sha256);
    }

    public static bool IsBlocked(ulong itemId, string folder)
    {
        if (ids.Contains(itemId.ToString())) return true;
        using (var sha = SHA256.Create())
            foreach (var dll in Directory.GetFiles(folder, "*.dll", SearchOption.AllDirectories))
                using (var s = File.OpenRead(dll))
                {
                    var hex = BitConverter.ToString(sha.ComputeHash(s)).Replace("-", "").ToLowerInvariant();
                    if (hashes.Contains(hex)) return true;
                }
        return false;
    }
}
```

Call `Fetch()` once at start-up (it waits at most 5 seconds), then `IsBlocked(id, folder)` for each mod before
loading it, and tell the player which mods were skipped and why.

## Limits

- Banning only works on games your publisher key controls.
- The blocklist only protects players whose game checks it. Games that never do still rely on the Workshop ban.
- WorkshopGuard's limits as a scanner apply here too (see the README). Review before you ban when you can.
