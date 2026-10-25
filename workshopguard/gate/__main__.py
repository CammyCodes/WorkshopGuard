"""WorkshopGuard launch gate.

  Steam launch options:   "<venv>\\Scripts\\pythonw.exe" "<repo>\\gate.pyw" %command%

  python -m workshopguard.gate install [game]     set those launch options (game: plateup, or an app ID)
  python -m workshopguard.gate uninstall [game]
  python -m workshopguard.gate scan [game]        check every mod now without starting the game
  python -m workshopguard.gate status [game]      what's installed, verdicts, recent launches
  python -m workshopguard.gate restore <id>       put a quarantined mod back and allow that exact version
  python -m workshopguard.gate forget <id>        drop remembered answers for a mod (it'll be asked about again)
  python -m workshopguard.gate guard [game]       stay running and check mods as Steam installs them, so even
                                                  starting the game's exe directly can't load an unchecked one
  python -m workshopguard.gate demo [game]        show the windows with made-up example mods (changes nothing)
  python -m workshopguard.gate run <game.exe> [args]   what Steam runs (also: just the exe path)
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
import traceback
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .. import games
from .config import GateConfig, home as gate_home

COMMANDS = {"install", "uninstall", "scan", "status", "restore", "forget", "run", "guard", "demo", "help", "-h", "--help"}
REPO = Path(__file__).resolve().parents[2]


def _logging(home: Path) -> None:
    home.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    fh = RotatingFileHandler(home / "gate.log", maxBytes=1 << 20, backupCount=2, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.addHandler(fh)
    if sys.stderr is not None and not os.environ.get("WG_GATE_QUIET"):
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(sh)


class _SingleInstance:
    """One gate per game at a time: a second Steam launch while the first is checking just steps aside."""
    def __init__(self, home: Path, appid: str):
        self.path = home / f"gate-{appid}.lock"
        self.fh = None

    def __enter__(self) -> bool:
        self.fh = open(self.path, "a+b")
        try:
            if os.name == "nt":
                import msvcrt
                self.fh.seek(0)
                msvcrt.locking(self.fh.fileno(), msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False

    def __exit__(self, *_):
        try:
            self.fh.close()
        except OSError:
            pass


def cmd_run(argv: list[str]) -> int:
    from .runner import Gate
    from .ui import UI
    home = gate_home()
    log = logging.getLogger("workshopguard.gate")
    if not argv:
        print("usage: gate.pyw <game.exe> [args]  (Steam: ... %command%)")
        return 2
    gate = None
    try:
        gate = Gate(argv, home=home)
        with _SingleInstance(home, str(gate.game.appid)) as first:
            if not first:
                log.warning("another gate is already running for app %s; not starting a second game", gate.game.appid)
                return 0
            return gate.run()
    except Exception as e:  # noqa: BLE001 - fail closed, but never leave the player stuck
        log.error("gate failed: %s\n%s", e, traceback.format_exc())
        if gate is not None:
            gate.release()
        name = gate.name if gate else Path(argv[0]).stem
        nomods = gate.adapter.nomods_arg if gate else None
        ui = gate.ui if gate else UI(name, theme=_configured_theme(home))
        buttons = (ui.s("error_quit"), ui.s("error_play_nomods") if nomods else ui.s("error_play"))
        pick = ui.alert(ui.s("error_title"), ui.s("error_body", error=e, log=home / "gate.log"), buttons, default=0)
        ui.close()
        if pick == buttons[1]:
            cmd = list(argv) + ([nomods] if nomods else [])
            return subprocess.call(cmd, cwd=str(Path(argv[0]).parent))
        return 1


def _configured_theme(home: Path) -> str:
    try:
        return GateConfig.load(home).theme or "default"
    except RuntimeError:
        return "default"


def _game(token: str | None):
    from . import adapters, steamlib
    appid = games.resolve(token or "plateup").appid
    return steamlib.locate(appid, adapters.for_appid(appid).exe_rel)


def cmd_scan(args: list[str]) -> int:
    from .runner import Gate
    os.environ.setdefault("WG_GATE_HEADLESS", "1")
    g = _game(args[0] if args else None)
    gate = Gate([str(g.exe)], home=gate_home(), game=g)
    t = time.perf_counter()
    todo = gate.check()
    print(f"{len(gate.items)} mods, {sum(len(i.files) for i in gate.items)} files hashed in "
          f"{(time.perf_counter() - t) * 1000:.0f} ms; {len(todo)} need scanning")
    gate.scan(todo, lambda text, frac=None: print(f"  {text}") if frac is None or text != "Done" else None)
    gate.release()
    print(f"{'item':<34} {'verdict':<11} reasons")
    for it in gate.items:
        res = gate.results[it.key]
        from .runner import _top
        why = "; ".join(f.description for f in _top(res.findings, 2))
        print(f"{it.title[:33]:<34} {res.verdict:<11} {why[:90]}")
    print(f"game files: {gate.gc.status}" + "".join(f"\n  ! {f.description} ({f.file})" for f in gate.gc.findings))
    for n in gate.scanner.notes:
        print(f"note: {n}")
    return 1 if any(gate.results[i.key].verdict == "malicious" for i in gate.items) else 0


class _Forever:
    """Stands in for the game process in guard mode: never exits unless stopped."""
    def __init__(self, stop=None):
        import threading
        self.stop = stop or threading.Event()
        self.returncode = 0

    def wait(self, timeout=None):
        if self.stop.wait(timeout):
            return 0
        raise subprocess.TimeoutExpired("guard", timeout)

    def poll(self):
        return 0 if self.stop.is_set() else None


def cmd_guard(args: list[str], stop=None) -> int:
    """Between launches: check every new or updated mod as soon as Steam has finished writing it."""
    from .runner import Gate
    g = _game(args[0] if args else None)
    gate = Gate([str(g.exe)], home=gate_home(), game=g)
    gate.cfg.verify_game_files = False   # the launch gate does that; guard only watches mods
    gate.cfg.watch_while_playing = True
    with _SingleInstance(gate.home, f"guard-{g.appid}") as first:
        if not first:
            print("A guard is already running for this game.")
            return 0
        todo = gate.check()
        gate.release()
        gate.scan(todo)
        for it in gate.items:
            res = gate.results.get(it.key)
            if res is not None and res.verdict == "malicious":
                gate.quarantine(it, res)
        logging.getLogger("workshopguard.gate").info("guard: watching %d mods of %s", len(gate.items), gate.name)
        gate.watch(_Forever(stop))
    return 0


def cmd_demo(args: list[str]) -> int:
    """What a player sees when Steam installs new mods and one is bad, with made-up mods. Nothing is scanned,
    moved or started. `demo plateup --theme branding/plateup` shows a theme folder."""
    from . import adapters
    from .ui import UI, Problem
    theme = None
    if "--theme" in args:
        i = args.index("--theme")
        theme = args[i + 1]
        args = args[:i] + args[i + 2:]
    appid = games.resolve(args[0] if args else "plateup").appid
    ad = adapters.for_appid(appid)
    name = ad.name or games.profile_for(appid).name
    ui = UI(name, 0.0, theme or GateConfig.load(gate_home()).theme or ad.theme)
    s = ui.s
    steps = [("Example: Free Hats (fake)", ["FreeHats.dll", "FreeHats.assets"]),
             ("Example: Odd Mod (fake)", ["OddMod.dll", "setup.bat"]),
             ("Example: Tidy Kitchen (fake)", ["TidyKitchen.dll", "TidyKitchen.assets", "TidyKitchen.pdb"])]
    total = sum(len(f) for _, f in steps)

    def fake_scan(progress):
        done = 0
        for title, files in steps:
            for f in files:
                progress(f"{title} · {f}", done / total)
                time.sleep(0.7)
                done += 1
        progress("Done", 1.0)

    ui.run(fake_scan, s("checking_many", n=3))
    ws = r"C:\Program Files (x86)\Steam\steamapps\workshop\content\{}\{}"
    problems = [
        Problem("demo:1", steps[0][0], f"{s('workshop_item', id=9000000001)} · {ws.format(appid, 9000000001)}",
                "malicious",
                [("Microsoft Defender: Trojan:MSIL/Stealer (example)", "FreeHats.dll"),
                 ("Reads account secrets and can send them over the internet (stealer pattern)", "FreeHats.dll"),
                 ("Contains a Discord webhook (common exfiltration)", "FreeHats.dll")],
                False, s("note_malicious_workshop")),
        Problem("demo:2", steps[1][0], f"{s('workshop_item', id=9000000002)} · {ws.format(appid, 9000000002)}",
                "suspicious", [(f"'.bat' files can run code on your PC; {name} items don't need them", "setup.bat")],
                True, s("note_suspicious")),
    ]
    ans = ui.ask(problems, gate_home() / "quarantine" / str(appid))
    if ans.action == "play":
        msg = s("demo_body_play", kept=s("demo_kept_allowed") if ans.allow else s("demo_kept_off"))
    else:
        msg = s("demo_body_quit")
    ui.alert(s("demo_title"), msg, (s("demo_close"),))
    ui.close()
    return 0


def cmd_status(args: list[str]) -> int:
    from .state import State
    appid = games.resolve(args[0] if args else "plateup").appid
    st = State(gate_home() / "gate.db")
    rows = st.items(appid)
    print(f"{'item':<34} {'kind':<9} {'verdict':<11} {'status':<12} {'scanned':<17} decision")
    for r in rows:
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["scanned_at"] or 0))
        dec = r["decision"] if r["decision"] else ""
        print(f"{(r['title'] or r['key'])[:33]:<34} {r['kind']:<9} {r['verdict']:<11} {r['status']:<12} {when:<17} {dec}")
    print("\nrecent launches:")
    for r in st.q("SELECT * FROM launches WHERE appid=? ORDER BY at DESC LIMIT 8", appid):
        print(f"  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r['at']))}  {r['outcome']:<16} "
              f"{r['ms']:>6} ms  {r['items']} mods, {r['scanned']} scanned  {r['detail']}")
    return 0


def cmd_restore(args: list[str]) -> int:
    import shutil
    from .state import State
    if not args:
        print("usage: restore <workshop id or local mod name>")
        return 2
    st = State(gate_home() / "gate.db")
    rows = [r for r in st.q("SELECT * FROM items WHERE status='quarantined'")
            if r["key"].rsplit(":", 1)[-1] == args[0].lower()]
    if not rows:
        print(f"Nothing called {args[0]} is in quarantine.")
        return 1
    r = rows[0]
    src, dst = Path(r["quarantine"]), Path(r["path"])
    if dst.exists():
        print(f"{dst} exists again (Steam re-downloaded it?); not overwriting. Quarantined copy: {src}")
    else:
        (src / "README_QUARANTINE.txt").unlink(missing_ok=True)
        (src / "WORKSHOPGUARD_README.txt").unlink(missing_ok=True)  # older gate versions
        shutil.move(str(src), str(dst))
        print(f"Moved back: {dst}")
    st.x("UPDATE items SET status='active', quarantine='', decision='allowed', decision_digest=digest WHERE key=?",
         r["key"])
    st.x("DELETE FROM bad WHERE item=?", r["key"])
    print("That exact version is allowed from now on; any change to it is checked again.")
    return 0


def cmd_forget(args: list[str]) -> int:
    from .state import State
    st = State(gate_home() / "gate.db")
    n = 0
    for r in st.q("SELECT key FROM items"):
        if args and r["key"].rsplit(":", 1)[-1] == args[0].lower():
            st.x("UPDATE items SET decision='', decision_digest='' WHERE key=?", r["key"])
            n += 1
    print(f"Forgot answers for {n} item(s).")
    return 0


def launch_value() -> str:
    pyw = Path(sys.executable).with_name("pythonw.exe")
    if not pyw.is_file():
        pyw = Path(sys.executable)
    return f'"{pyw}" "{REPO / "gate.pyw"}" %command%'


def cmd_install(args: list[str], remove: bool = False) -> int:
    from . import steamlib
    token = next((a for a in args if not a.startswith("-")), None)
    appid = games.resolve(token or "plateup").appid
    value = None if remove else launch_value()
    root = steamlib.steam_root()
    configs = steamlib.localconfigs(root) if root else []
    if not remove:
        print("Launch options for Steam (right-click the game > Properties > Launch Options):\n\n  " + value + "\n")
    if not configs:
        print("Couldn't find Steam's userdata folder; paste the line above into Steam yourself.")
        return 1
    if steamlib.steam_running():
        if not remove:
            subprocess.run("clip", input=value, text=True, shell=True, check=False)
            print("Steam is running, so it can't be changed from here (Steam would overwrite it on exit). It's on "
                  "your clipboard: paste it into the game's Launch Options, or close Steam and run this again.")
        else:
            print("Steam is running: clear the game's Launch Options in Steam, or close Steam and run this again.")
        return 3
    for lc in configs:
        bak = lc.with_suffix(f".vdf.wg-{time.strftime('%Y%m%d-%H%M%S')}.bak")
        bak.write_bytes(lc.read_bytes())
        try:
            old = steamlib.set_launch_options(lc, appid, value)
        except RuntimeError as e:
            print(f"{lc}: {e}")
            continue
        now = steamlib.get_launch_options(lc, appid)
        print(f"{lc.parent.parent.name}: {'cleared' if remove else 'set'} (was: {old or 'empty'}; now: {now or 'empty'})")
        if old and not remove and "gate.pyw" not in old:
            print("  Note: your old launch options were replaced. Add game arguments after %command%.")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    _logging(gate_home())
    if not argv or argv[0] in ("help", "-h", "--help"):
        print(__doc__)
        return 0
    if argv[0] not in COMMANDS:  # Steam: gate.pyw <exe> [args]
        return cmd_run(argv)
    cmd, rest = argv[0], argv[1:]
    if cmd == "run":
        return cmd_run(rest)
    return {"install": lambda a: cmd_install(a), "uninstall": lambda a: cmd_install(a, remove=True),
            "scan": cmd_scan, "status": cmd_status, "guard": cmd_guard, "demo": cmd_demo, "restore": cmd_restore, "forget": cmd_forget}[cmd](rest)


if __name__ == "__main__":
    sys.exit(main())
