"""One launch: check, decide, start the game, confirm what it loaded, then keep watch until it closes."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..scan.model import MALICIOUS, SUSPICIOUS, Finding, ScanResult
from . import adapters, integrity, inventory, scanner, steamlib
from .config import GateConfig, home as gate_home
from .state import State
from .ui import UI, Problem

log = logging.getLogger("workshopguard.gate")
WATCH_SECONDS = 10


class Gate:
    def __init__(self, cmd: list[str], cfg: GateConfig | None = None, home: Path | None = None,
                 game: steamlib.Game | None = None):
        self.home = home or gate_home()
        self.cfg = cfg or GateConfig.load(self.home)
        self.cmd = cmd
        env_app = os.environ.get("SteamAppId") or os.environ.get("SteamGameId") or ""
        self.game = game or steamlib.find_game(
            cmd, int(env_app) if env_app.isdigit() and int(env_app) < 1 << 32 else None)
        self.adapter = adapters.for_appid(self.game.appid)
        self.name = self.adapter.name or self.scanner_profile_name()
        self.st = State(self.home / "gate.db")
        self.scanner = scanner.Scanner(self.home, self.cfg, self.st, self.game.appid)
        self.ui = UI(self.name, self.cfg.splash_after, self.adapter.theme)
        self.qdir = self.home / "quarantine" / str(self.game.appid)
        self.items: list[inventory.Item] = []
        self.results: dict[str, ScanResult] = {}
        self.scanned = 0
        self.blocked: list[inventory.Item] = []
        self.gc = integrity.GameCheck(status="off")
        self.stop = threading.Event()

    def scanner_profile_name(self) -> str:
        from .. import games
        return games.profile_for(self.game.appid).name

    # --- 1-3: inventory, hashes, cached verdicts ---------------------------------------------------------------
    def check(self) -> list[inventory.Item]:
        """Hash everything and return the items that need scanning."""
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="blocklist") as ex:
            bl = ex.submit(scanner.load_blocklists, self.cfg, self.game.appid, self.st)
            self.items = inventory.collect(self.game, self.adapter)
            inventory.hash_items(self.items, self.adapter, lock=True)
            if self.cfg.verify_game_files:
                self.gc = integrity.check(self.game, self.st, self.adapter.mods_root(self.game))
            self.scanner.blocklist, notes = bl.result()
        for n in notes:
            log.info("blocklist: %s", n)
        todo = []
        for it in self.items:
            row = self.st.item(it.key)
            if row and row["title"] and row["title"] != it.id:
                it.title = row["title"]
            if (row and row["digest"] == it.digest and row["engines"] == self.scanner.engines and not it.busy
                    and not any(n.severity in ("high", "critical") for n in it.notes)
                    and not self.scanner.known_bad(it) and row["status"] == "active"):
                self.results[it.key] = _from_row(row)
            else:
                todo.append(it)
        return todo

    # --- 4: scan --------------------------------------------------------------------------------------------------
    def scan(self, todo: list[inventory.Item], progress=None) -> None:
        ws = [it.id for it in todo if it.kind == "workshop"]
        names: dict[str, str] = {}
        tt = threading.Thread(target=lambda: names.update(scanner.titles(ws, self.st)), daemon=True) if ws else None
        if tt:
            tt.start()
        total = len(todo) + (1 if self.gc.files else 0)
        for i, it in enumerate(todo):
            if progress:
                progress(f"{it.title}", i / max(total, 1))

            def file_cb(rel, n, m, i=i, it=it):
                if progress:
                    progress(f"{it.title} · {rel.rsplit('/', 1)[-1]}", (i + (n / max(m, 1))) / max(total, 1))
            t = time.perf_counter()
            res = self.scanner.scan(it, file_cb)
            self.st.save_item(it, res, self.scanner.engines)
            self.results[it.key] = res
            self.scanned += 1
            log.info("scanned %s (%s): %s in %.2fs, %s", it.key, it.title, res.verdict, time.perf_counter() - t,
                     res.engines)
        if self.gc.files:
            if progress:
                progress(f"{self.name} game files", len(todo) / max(total, 1))
            g = inventory.Item(f"game:{self.game.appid}", self.game.appid, "game", self.game.install_dir, "game",
                               f"{self.name} game files", files=dict(self.gc.files))
            res = self.scanner.scan(g)
            self.gc.findings += [f for f in res.findings if f.severity in ("medium", "high", "critical")]
        if tt:
            tt.join(3)
            for it in todo:
                if names.get(it.id) and names[it.id] != it.title:
                    it.title = names[it.id]
                    self.st.x("UPDATE items SET title=? WHERE key=?", it.title, it.key)
        if progress:
            progress("Done", 1.0)

    # --- 5: decide ------------------------------------------------------------------------------------------------
    def problems(self) -> tuple[list[Problem], list[inventory.Item]]:
        """(things to ask about, items to block without asking)."""
        ask, block = [], []
        for it in self.items:
            res = self.results.get(it.key)
            if res is None or res.verdict not in (MALICIOUS, SUSPICIOUS):
                continue
            row = self.st.item(it.key)
            decided = row and row["decision_digest"] == it.digest and row["decision"]
            if decided == "allowed":  # the player's call on this exact version (malicious: only via `restore`)
                continue
            if res.verdict == SUSPICIOUS:
                if self.cfg.suspicious == "allow":
                    continue
                if decided == "blocked" or self.cfg.suspicious == "block":
                    block.append(it)
                    continue
            ask.append(self._problem(it, res))
        if self.gc.flagged:
            ask.append(Problem(f"game:{self.game.appid}", f"{self.name}'s own files", str(self.game.install_dir),
                               "game", [(f.description, f.file) for f in _top(self.gc.findings)], can_allow=True,
                               note="If you didn't install anything into the game folder, repair it with Steam."))
        return ask, block

    def _problem(self, it, res: ScanResult) -> Problem:
        where = (f"Steam Workshop item {it.id}" if it.kind == "workshop" else f"Local mod folder") + f" · {it.path}"
        link = f"https://steamcommunity.com/sharedfiles/filedetails/?id={it.id}" if it.kind == "workshop" else ""
        mal = res.verdict == MALICIOUS
        note = ("It will be moved to quarantine. Unsubscribe from it on Steam and report it."
                if mal and it.kind == "workshop" else "It will be moved to quarantine." if mal else
                "Left off unless you tick the box. Your answer is remembered until the mod changes.")
        return Problem(it.key, it.title, where, res.verdict, [(f.description, f.file) for f in _top(res.findings)],
                       can_allow=not mal, note=note, link=link)

    def apply(self, ask: list[Problem], allow: set[str], block: list[inventory.Item]) -> bool:
        """Record decisions and move blocked items out. Returns False if something couldn't be moved."""
        ok = True
        by_key = {it.key: it for it in self.items}
        for p in ask:
            if p.verdict == "game":
                if p.key in allow:
                    integrity.approve(self.game, self.st, self.gc)
                continue
            it = by_key[p.key]
            if p.key in allow:
                self.st.decide(it.key, "allowed", it.digest)
                log.warning("player allowed %s (%s) digest %s", it.key, it.title, it.digest[:12])
            else:
                if p.verdict == SUSPICIOUS:
                    self.st.decide(it.key, "blocked", it.digest)
                block.append(it)
        for it in block:
            ok &= self.quarantine(it, self.results[it.key])
        return ok

    def quarantine(self, it: inventory.Item, res: ScanResult) -> bool:
        it.release()
        stamp = time.strftime("%Y%m%d-%H%M%S")
        dest = self.qdir / f"{it.kind}-{it.id}-{stamp}"
        # Rename in place first (atomic, and the game then can't find it), then move it out to the quarantine.
        hidden = it.path.with_name(f".wg-blocked-{it.path.name}-{stamp}")
        try:
            os.rename(it.path, hidden)
        except OSError as e:
            log.error("couldn't move %s aside: %s", it.path, e)
            return False
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(hidden), str(dest))
        except OSError as e:
            log.warning("moved %s aside to %s but not into the quarantine (%s)", it.path, hidden, e)
            dest = hidden
        try:
            (dest / "WORKSHOPGUARD_README.txt").write_text(
                f"WorkshopGuard's launch gate moved this mod here before {self.name} could load it.\n"
                f"Verdict: {res.verdict}\nFrom: {it.path}\n\n"
                + "\n".join(f"- {f.description} ({f.file})" for f in _top(res.findings, 12))
                + "\n\nDon't open or run anything in this folder. Unsubscribe from it on Steam.\n"
                  "To put it back anyway: python -m workshopguard.gate restore " + it.id + "\n", encoding="utf-8")
        except OSError:
            pass
        self.st.x("UPDATE items SET status='quarantined', quarantine=? WHERE key=?", str(dest), it.key)
        if res.verdict == MALICIOUS:
            self._remember_bad(it, res)
        self.blocked.append(it)
        log.warning("QUARANTINED %s (%s, %s) -> %s", it.key, it.title, res.verdict, dest)
        return True

    def _remember_bad(self, it, res: ScanResult) -> None:
        """Remember the files that made it malicious, so the same payload is stopped instantly next time, but never a
        file that also ships in a clean mod (a bad mod bundling 0Harmony.dll mustn't block every Harmony mod)."""
        safe = self.st.clean_hashes()
        flagged = {f.file.split("!", 1)[0] for f in res.findings if f.file and f.severity in ("high", "critical")}
        if not flagged:
            flagged = {r for r in it.files if r.lower().endswith((".dll", ".exe"))}
        why = next((f.description for f in res.findings if f.severity == "critical"), res.verdict)[:200]
        rows = [(it.files[r][0], it.key, it.title, why) for r in flagged if r in it.files
                and it.files[r][0] not in safe]
        self.st.add_bad(rows)
        self.scanner.forget_bad_cache()

    # --- 6-8: launch, confirm, watch ----------------------------------------------------------------------------
    def launch(self, nomods: bool = False) -> subprocess.Popen:
        cmd = list(self.cmd)
        if nomods and self.adapter.nomods_arg and self.adapter.nomods_arg not in cmd:
            cmd.append(self.adapter.nomods_arg)
        log.info("starting %s", subprocess.list2cmdline(cmd))
        return subprocess.Popen(cmd, cwd=str(self.game.exe.parent))

    def release(self) -> None:
        for it in self.items:
            it.release()

    def confirm_load(self, proc, started: float) -> bool:
        """For games that log what they load: hold the locks until it has, and check it used only checked folders."""
        vetted = {adapters.norm(it.path) for it in self.items if it not in self.blocked}
        root = self.adapter.mods_root(self.game)
        if root is not None:
            vetted.add(adapters.norm(root))
        try:
            rep = self.adapter.watch_load(proc, started, vetted)
        finally:
            self.release()
        if rep is None:
            log.info("game didn't confirm loading mods (no log, or closed early)")
            return True
        log.info("game loaded mods %.1fs after start from %d folder(s)%s", rep.seconds, len(rep.loaded_dirs),
                 " (mods disabled)" if rep.mods_disabled else "")
        if rep.unvetted:
            log.error("game loaded UNCHECKED folders: %s", rep.unvetted)
            proc.kill()
            self.ui.alert(f"WorkshopGuard closed {self.name}",
                          "It started loading mods from folders that weren't checked first:\n\n"
                          + "\n".join(rep.unvetted[:6]) + "\n\nStart the game again and they'll be checked.")
            return False
        return True

    def watch(self, proc) -> None:
        """While the game runs: pre-scan anything Steam updates or adds, at low priority. Malicious → quarantined
        at once (the running game still has the earlier, checked version loaded)."""
        _lower_priority()
        if self.cfg.verify_game_files and self.gc.status != "updating":
            threading.Thread(target=self._verify_game, daemon=True, name="game-verify").start()
        if not self.cfg.watch_while_playing:
            proc.wait()
            return
        seen = {it.key: inventory.fingerprint(it.path) for it in self.items if it not in self.blocked}
        pending: dict[str, str] = {}
        while True:
            try:
                proc.wait(timeout=WATCH_SECONDS)
                return
            except subprocess.TimeoutExpired:
                pass
            try:
                for it in inventory.collect(self.game, self.adapter):
                    fp = inventory.fingerprint(it.path)
                    if seen.get(it.key) == fp:
                        pending.pop(it.key, None)
                        continue
                    if pending.get(it.key) != fp:   # still changing (Steam mid-download): look again next time
                        pending[it.key] = fp
                        continue
                    pending.pop(it.key, None)
                    seen[it.key] = fp
                    self._scan_live(it)
            except Exception:  # noqa: BLE001 - never take the game down with us
                log.exception("watch: check failed")

    def _scan_live(self, it: inventory.Item) -> None:
        inventory.hash_items([it], self.adapter, lock=False)
        row = self.st.item(it.key)
        if row and row["digest"] == it.digest and row["engines"] == self.scanner.engines:
            return
        res = self.scanner.scan(it)
        self.st.save_item(it, res, self.scanner.engines)
        log.info("watch: %s (%s) changed while playing: %s", it.key, it.title, res.verdict)
        if res.verdict == MALICIOUS:
            self.quarantine(it, res)
            self.ui.alert(f"WorkshopGuard blocked an update to '{it.title}'",
                          "Steam just downloaded an update to this mod and it looks malicious:\n\n"
                          + "\n".join(f"•  {f.description}" for f in _top(res.findings, 4))
                          + "\n\nIt's been moved to quarantine before it could load. The copy in this game session "
                            "is the earlier version, which was checked. Unsubscribe from it on Steam.")

    def _verify_game(self) -> None:
        try:
            time.sleep(20)  # let the game finish loading first
            bad = integrity.full_verify(self.game, self.st, self.adapter.mods_root(self.game), self.stop)
            if bad:
                log.error("game files changed without their dates changing: %s", bad)
        except Exception:  # noqa: BLE001
            log.exception("game verify failed")

    # --- the whole thing ------------------------------------------------------------------------------------------
    def run(self) -> int:
        t0 = time.perf_counter()
        todo = self.check()
        log.info("checked %d mods (%d files) in %.0f ms; %d to scan; game files: %s", len(self.items),
                 sum(len(i.files) for i in self.items), (time.perf_counter() - t0) * 1000, len(todo), self.gc.status)
        if todo or self.gc.files:
            n = len(todo)
            heading = (f"Checking {n} new or updated mod{'s' if n != 1 else ''}…" if n else
                       f"Checking {self.name}'s files…")
            self.ui.run(lambda progress: self.scan(todo, progress), heading)
        for n in self.scanner.notes:
            log.warning(n)
        ask, block = self.problems()
        nomods = False
        if ask:
            ans = self.ui.ask(ask, self.qdir)
            log.info("player chose %s (allowed: %s)", ans.action, sorted(ans.allow))
            if ans.action in ("quit", "repair"):
                # malicious ones go to quarantine either way, so starting the exe directly can't load them
                self.apply([p for p in ask if p.verdict == MALICIOUS], set(), block)
                self.release()
                if ans.action == "repair" and os.name == "nt":
                    os.startfile(f"steam://validate/{self.game.appid}")
                self._log_launch(t0, ans.action)
                return 0
            if not self.apply(ask, ans.allow, block):
                nomods = True
        elif block:
            if not self.apply([], set(), block):
                nomods = True
        if nomods:
            if self.adapter.nomods_arg is None:
                self.release()
                self.ui.alert("WorkshopGuard couldn't move a blocked mod",
                              "Its folder is in use. Close anything using it and start the game again.")
                self._log_launch(t0, "move-failed")
                return 1
            self.ui.alert("WorkshopGuard couldn't move a blocked mod",
                          f"Its folder is in use, so {self.name} will start with mods turned off this time.")
        self.ui.close()
        pre_ms = (time.perf_counter() - t0) * 1000
        started = time.time()
        proc = self.launch(nomods)
        self._log_launch(t0, "launched-nomods" if nomods else "launched", pre_ms)
        log.info("game started %.0f ms after Steam asked (%d scanned, %d blocked)", pre_ms, self.scanned,
                 len(self.blocked))
        if not self.confirm_load(proc, started):
            return 1
        self.watch(proc)
        self.stop.set()
        return proc.returncode or 0

    def _log_launch(self, t0: float, outcome: str, ms: float | None = None) -> None:
        ms = ms if ms is not None else (time.perf_counter() - t0) * 1000
        self.st.log_launch(self.game.appid, int(ms), len(self.items), self.scanned, outcome,
                           json.dumps({"blocked": [i.key for i in self.blocked], "game": self.gc.status}))


def _from_row(row) -> ScanResult:
    fs = [Finding(**f) for f in json.loads(row["findings"] or "[]")]
    return ScanResult(row["verdict"], row["score"] or 0, fs, 0, 0, {})


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _top(findings: list[Finding], n: int = 8) -> list[Finding]:
    """Most serious first, one line per distinct reason."""
    seen, out = set(), []
    for f in sorted(findings, key=lambda f: SEV_ORDER.get(f.severity, 9)):
        if f.severity in ("info", "low") or (f.rule, f.file) in seen:
            continue
        seen.add((f.rule, f.file))
        out.append(f)
    return out[:n]


def _lower_priority() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes
        k = ctypes.windll.kernel32
        k.SetPriorityClass(k.GetCurrentProcess(), 0x4000)  # BELOW_NORMAL_PRIORITY_CLASS (set after the game started)
    except Exception:  # noqa: BLE001
        pass
