"""Command line: `workshopguard <command>` (in Docker: `docker compose run --rm guard <command>`)."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from . import __version__, config, downloader, games, steam, testdata
from .scan.model import SEVERITY_WEIGHT

log = logging.getLogger("workshopguard")


verbose = False


def _print_result(title: str, res) -> None:
    print(f"\n== {title}\n   verdict: {res.verdict.upper()}  score: {res.score}  files: {res.files_scanned}")
    minor = sum(f.severity in ("low", "info") for f in res.findings)
    for f in sorted(res.findings, key=lambda f: -SEVERITY_WEIGHT[f.severity]):
        if f.severity in ("low", "info") and not verbose:
            continue
        print(f"   [{f.severity:<8}] {f.description}" + (f"  ({f.file})" if f.file else ""))
        for e in f.evidence[:3]:
            print(f"              {e}")
    if minor and not verbose:
        print(f"   (+{minor} low/info notes; -v to show them)")
    if res.engines:
        print()
        print("   engine                                   files  flagged  result")
        for e in res.engines.values():
            if e["errors"] and not e["detections"]:
                result = f"{e['errors']} error(s)"
            elif e["detections"]:
                result = "FLAGGED"
            elif e.get("notes"):
                result = f"clean ({e['notes']} file(s) worth a look)"
            elif e["files"] == 0:
                result = "nothing to check"
            elif e["unknown"] == e["files"]:
                result = "never seen these files"
            else:
                result = "clean"
            print(f"   {e['label']:<40} {e['files']:>5}  {e['detections']:>7}  {result}")


def cmd_watch(cfg, args):
    from .pipeline import Guard
    from .web import Dashboard
    from .protect import Protector
    from .web import BlocklistServer
    guard = Guard(cfg, watcher=True)
    Dashboard(guard.db, cfg.dashboard_host, cfg.dashboard_port, guard.moderator, cfg.admin_password).start()
    if guard.moderator.api:
        log.info("Publisher mode: moderating %s, AUTO_BAN=%s",
                 ", ".join(games.profile_for(a).name for a in sorted(cfg.publisher_apps)), cfg.auto_ban)
        BlocklistServer(guard.db, cfg.blocklist_port, cfg.publisher_apps).start()
    protector = Protector(guard)
    if protector.enabled():
        protector.start_thread()
    guard.run_forever()


def cmd_protect(cfg, args):
    """Only guard the mods on this PC (no Workshop watching)."""
    from .pipeline import Guard
    from .protect import Protector
    from .web import Dashboard
    guard = Guard(cfg)
    protector = Protector(guard)
    if not protector.enabled():
        print(f"Nothing to protect: mount Steam's workshop/content folder at {cfg.protect_dir} "
              f"(it should contain folders named {', '.join(str(g.appid) for g in cfg.games)}).")
        return 2
    Dashboard(guard.db, cfg.dashboard_host, cfg.dashboard_port).start()
    if args.once:
        n = protector.sweep()
        print(f"Scanned {n} new/changed item(s).")
        return 0
    protector.run_forever()


def cmd_scan_item(cfg, args):
    from .pipeline import Guard
    guard = Guard(cfg, deep=args.deep, upload=args.upload or None)
    p = games.resolve(args.game)
    items = {it.id: it for it in steam.details(args.ids, p.appid)}
    missing = [i for i in args.ids if i not in items]
    if missing:
        print(f"Not found / not public: {', '.join(missing)}")
    worst = 0
    for it in items.values():
        guard.db.upsert_seen(it)
        res = guard.dl.download(p.appid, [it.id], it.file_size).get(it.id)
        guard.db.set("anon_ok", {str(k): v for k, v in guard.dl.anon_ok.items()})
        if not res or not res.path:
            print(f"\n== {it.title} ({it.id})\n   download failed: {res.error if res else '?'}")
            guard.db.set_status(p.appid, it.id, "error", f"Download failed: {res.error if res else '?'}")
            worst = max(worst, 3)
            continue
        try:
            r = guard.scan_and_record(p, it, res.path, inject_test=args.inject_test, notify=not args.no_notify)
        finally:
            if not args.keep:
                guard.dl.cleanup(p.appid, it.id)
        _print_result(f"{it.title} ({it.id}) {it.url}", r)
        worst = max(worst, {"clean": 0, "suspicious": 1, "malicious": 2}[r.verdict])
    return worst


def cmd_scan_path(cfg, args):
    """Scan a folder already on disk, e.g. your own Steam workshop/content/<appid> folder mounted read-only."""
    from .pipeline import Guard
    guard = Guard(cfg, deep=args.deep, upload=args.upload or None)
    root = Path(args.path)
    p = games.resolve(args.game)
    folders = [root] if args.single else sorted(d for d in root.iterdir() if d.is_dir())
    worst = 0
    for d in folders:
        it = steam.Item(p.appid, d.name, title=d.name)
        if d.name.isdigit() and not args.offline:
            got = steam.details([d.name], p.appid)
            it = got[0] if got else it
        r = guard.scan_and_record(p, it, d, notify=not args.no_notify)
        _print_result(f"{it.title} ({d})", r)
        worst = max(worst, {"clean": 0, "suspicious": 1, "malicious": 2}[r.verdict])
    return worst


def cmd_selftest(cfg, args):
    """Fake detection, end to end: download a real item, plant harmless test files, scan, record and alert."""
    from .pipeline import Guard
    guard = Guard(cfg)
    ok = True
    print(f"WorkshopGuard {__version__} self-test")
    print(f"  YARA rule files: {len(guard.scanners.yara.sources) if guard.scanners.yara else 0}")
    print(f"  ClamAV: {guard.scanners.clamav.version() if guard.scanners.clamav else 'off (CLAMAV_HOST not set)'}")
    print(f"  Alerts: {'on' if guard.notifier.enabled else 'off (no DISCORD_WEBHOOK_URL / WEBHOOK_URL)'}")
    p = games.resolve(args.game)
    item_id = args.item
    if not item_id:
        # smallest of the newest items, so the test is quick
        items, _ = steam.browse_page(p.appid, "mostrecent", 1)
        item_id = min(items, key=lambda i: i.file_size).id
    it = steam.details([item_id], p.appid)[0]
    print(f"  Test item: {it.title} ({it.id}, {it.file_size // 1024} KB) for {p.name}")
    res = guard.dl.download(p.appid, [it.id], it.file_size).get(it.id)
    guard.db.set("anon_ok", {str(k): v for k, v in guard.dl.anon_ok.items()})
    if not res or not res.path:
        print(f"  DOWNLOAD FAILED: {res.error if res else '?'}")
        return 3
    try:
        r = guard.scan_and_record(p, it, res.path, inject_test=True, notify=not args.no_notify)
    finally:
        guard.dl.cleanup(p.appid, it.id)
    _print_result(f"{it.title} + planted test files", r)
    rules = {f.rule for f in r.findings}
    checks = [("YARA caught the test marker", "yara.WorkshopGuard_Test_Marker" in rules)]
    if guard.scanners.clamav:
        checks.append(("ClamAV caught the EICAR test file", "clamav.detected" in rules))
    checks.append(("Verdict is MALICIOUS", r.verdict == "malicious"))
    checks.append(("Saved to the database", (guard.db.item(p.appid, it.id) or {})["is_test"] == 1))
    if guard.notifier.enabled and not args.no_notify:
        checks.append(("Alert delivered", bool(guard.notifier.sent)))
    print()
    for name, passed in checks:
        ok &= passed
        print(f"  {'PASS' if passed else 'FAIL'}  {name}")
    print(f"\nSelf-test {'PASSED' if ok else 'FAILED'}.")
    return 0 if ok else 1


def cmd_login(cfg, args):
    return downloader.interactive_login(args.username or cfg.steam_username)


def cmd_list(cfg, args):
    p = games.resolve(args.game)
    for it in steam.iter_items(p.appid, args.sort, args.pages):
        print(f"{it.id}  {it.file_size / 1048576:9.1f} MB  {time.strftime('%Y-%m-%d %H:%M', time.gmtime(it.time_updated))}"
              f"  {it.title[:70]}")


def cmd_status(cfg, args):
    from .db import DB
    db = DB(cfg.db_path)
    print(json.dumps({games.profile_for(a).name: s for a, s in db.stats().items()}, indent=2))
    for r in db.q("""SELECT appid,id,title,verdict,score FROM items WHERE status='scanned'
                     AND verdict IN ('malicious','suspicious') ORDER BY scanned_at DESC LIMIT 30"""):
        print(f"{r['verdict']:<10} {r['score']:>4}  {r['id']}  {r['title']}")


def _moderator(cfg):
    from .db import DB
    from .moderation import Moderator
    from .notify import Notifier
    db = DB(cfg.db_path)
    return db, Moderator(cfg, db, Notifier(cfg.discord_webhook_url, cfg.webhook_url, cfg.notify_on, cfg.public_url))


def cmd_moderate(cfg, args):
    """ban / unban / ban-uploader / unban-uploader for the game's own developer (needs PUBLISHER_KEY)."""
    from .moderation import PublisherError, ban_reason
    db, mod = _moderator(cfg)
    p = games.resolve(args.game)
    try:
        for target in args.ids:
            row = db.item(p.appid, target)
            if args.cmd == "ban":
                if row is None:  # never scanned: record it so the blocklist and log have a title
                    got = steam.details([target], p.appid)
                    if got:
                        db.upsert_seen(got[0])
                    row = db.item(p.appid, target)
                findings = json.loads(row["findings"] or "[]") if row else []
                ok = mod.ban_item(p.appid, target, args.reason or ban_reason(findings), by="cli")
            elif args.cmd == "unban":
                ok = mod.unban_item(p.appid, target, by="cli")
            elif args.cmd == "ban-uploader":
                creator = row["creator"] if row else target  # an item ID, or a SteamID64 directly
                ok = mod.ban_uploader(p.appid, row["id"] if row else "", creator, by="cli", days=args.days)
            else:
                ok = mod.unban_uploader(p.appid, target, by="cli")
            print(f"{args.cmd} {target}: {'done' if ok else 'FAILED (see the log)'}")
    except PublisherError as e:
        print(e, file=sys.stderr)
        return 2
    return 0


def cmd_blocklist(cfg, args):
    from .moderation import blocklist
    db, _ = _moderator(cfg)
    print(json.dumps(blocklist(db, games.resolve(args.game).appid), indent=1))


def cmd_rescan(cfg, args):
    from .db import DB
    db = DB(cfg.db_path)
    if args.all:
        db.x("UPDATE items SET status='queued' WHERE status IN ('scanned','error')")
    else:
        for i in args.ids:
            db.x("UPDATE items SET status='queued' WHERE id=?", i)
    print("Queued; the watcher picks them up on its next check.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="workshopguard", description="Scan Steam Workshop items for malware.")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("watch", help="Run forever: watch the Workshop, scan new and updated items (default)")
    s = sub.add_parser("scan-item", help="Download and scan specific items")
    s.add_argument("game")
    s.add_argument("ids", nargs="+")
    s.add_argument("--inject-test", action="store_true", help="Plant harmless fake-malware files to test detection")
    s.add_argument("--no-notify", action="store_true")
    s.add_argument("--keep", action="store_true", help="Keep the downloaded files in /data/work")
    s.add_argument("--deep", action="store_true", help="Run every engine available (same as deep-scan)")
    s.add_argument("--upload", action="store_true",
                   help="Upload files VirusTotal/MetaDefender have never seen, for a full multi-engine scan")
    s = sub.add_parser("deep-scan", help="Scan items with every engine available and show what each one said")
    s.add_argument("game")
    s.add_argument("ids", nargs="+")
    s.add_argument("--upload", action="store_true",
                   help="Upload files VirusTotal/MetaDefender have never seen, for a full multi-engine scan")
    s.add_argument("--inject-test", action="store_true")
    s.add_argument("--no-notify", action="store_true")
    s.add_argument("--keep", action="store_true")
    s.set_defaults(deep=True)
    s = sub.add_parser("protect", help="Guard the mods installed on this PC (mount Steam's workshop/content at /protect)")
    s.add_argument("--once", action="store_true", help="Scan once and exit")
    s = sub.add_parser("scan-path", help="Scan folders already on disk (each subfolder = one item)")
    s.add_argument("game")
    s.add_argument("path")
    s.add_argument("--single", action="store_true", help="PATH is one item, not a folder of items")
    s.add_argument("--offline", action="store_true", help="Don't look item titles up on Steam")
    s.add_argument("--no-notify", action="store_true")
    s.add_argument("--deep", action="store_true", help="Run every engine available")
    s.add_argument("--upload", action="store_true")
    s = sub.add_parser("selftest", help="Fake detection end to end (real download + planted test files + alert)")
    s.add_argument("game", nargs="?", default="")
    s.add_argument("--item", default="")
    s.add_argument("--no-notify", action="store_true")
    s = sub.add_parser("login", help="Log SteamCMD in once (password + Steam Guard); the login is cached")
    s.add_argument("username", nargs="?", default="")
    s = sub.add_parser("list", help="List Workshop items")
    s.add_argument("game")
    s.add_argument("--sort", default="mostrecent", choices=["mostrecent", "lastupdated"])
    s.add_argument("--pages", type=int, default=1)
    for name, helptext in (("ban", "Ban Workshop items for everyone (game developers, needs PUBLISHER_KEY)"),
                           ("unban", "Undo a ban"),
                           ("ban-uploader", "Stop an uploader posting Workshop items for your game (item ID or SteamID)"),
                           ("unban-uploader", "Lift an uploader ban (SteamID)")):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("game")
        s.add_argument("ids", nargs="+")
        if name == "ban":
            s.add_argument("--reason", default="", help="Shown to Steam admins only")
        if name == "ban-uploader":
            s.add_argument("--days", type=int, default=None, help="Default UPLOADER_BAN_DAYS (0 = permanent)")
    s = sub.add_parser("blocklist", help="Print the blocklist your game can check at load time")
    s.add_argument("game")
    sub.add_parser("status", help="Counts and the latest flagged items")
    s = sub.add_parser("rescan", help="Queue items for another scan (e.g. after adding rules)")
    s.add_argument("ids", nargs="*")
    s.add_argument("--all", action="store_true")
    args = ap.parse_args(argv)

    global verbose
    verbose = args.verbose
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    try:
        cfg = config.load()
    except ValueError as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 2
    if getattr(args, "game", None) == "":
        args.game = str(cfg.games[0].appid)
    cmd = args.cmd or "watch"
    fn = {"watch": cmd_watch, "scan-item": cmd_scan_item, "deep-scan": cmd_scan_item, "protect": cmd_protect, "scan-path": cmd_scan_path, "selftest": cmd_selftest,
          "login": cmd_login, "list": cmd_list, "ban": cmd_moderate, "unban": cmd_moderate,
          "ban-uploader": cmd_moderate, "unban-uploader": cmd_moderate, "blocklist": cmd_blocklist, "status": cmd_status, "rescan": cmd_rescan}[cmd]
    try:
        return fn(cfg, args) or 0
    except ValueError as e:
        print(e, file=sys.stderr)
        return 2
