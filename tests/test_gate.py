"""Launch gate tests: a fake Steam library, a fake PlateUp (gate_fakegame.py) and real engines (WorkshopGuard's YARA
rules, the .NET analyzer and Microsoft Defender when present). Windows only, since that's where the gate runs:

    .gate\\venv\\Scripts\\python -m pytest -q tests/test_gate.py
"""

import json
import os
import shutil
import sys
import threading
import time
from pathlib import Path

import pytest

if os.name != "nt":
    pytest.skip("the launch gate runs on Windows", allow_module_level=True)

from workshopguard import testdata
from workshopguard.gate import defender, integrity, runner, steamlib
from workshopguard.gate.config import GateConfig
from workshopguard.gate.runner import Gate

HERE = Path(__file__).parent
FAKEGAME = HERE / "gate_fakegame.py"
STEALER = HERE / "fixtures" / "out" / "plateup" / "9000000001" / "FakeStealerMod.dll"
APPID = 1599600


class Lib:
    """A throwaway Steam library with PlateUp in it."""

    def __init__(self, tmp: Path, monkeypatch):
        self.tmp = tmp
        self.steamapps = tmp / "lib" / "steamapps"
        self.install = self.steamapps / "common" / "PlateUp"
        self.exe_dir = self.install / "PlateUp"
        self.ws = self.steamapps / "workshop" / "content" / str(APPID)
        self.mods = self.exe_dir / "Mods"
        self.home = tmp / "home"
        self.result = tmp / "result.json"
        for d in (self.ws, self.mods, self.exe_dir / "PlateUp_Data" / "Managed"):
            d.mkdir(parents=True)
        (self.exe_dir / "PlateUp.exe").write_bytes(b"MZ fake game")
        (self.exe_dir / "UnityPlayer.dll").write_bytes(b"MZ fake unity" + os.urandom(64))
        (self.exe_dir / "PlateUp_Data" / "Managed" / "Assembly-CSharp.dll").write_bytes(b"MZ fake" + os.urandom(64))
        self.buildid = "100"
        env = {"WG_GATE_HOME": str(self.home), "WG_GATE_HEADLESS": "1", "WG_GATE_QUIET": "1",
               "WG_STEAM_ROOT": str(tmp / "no-steam"), "WG_PLAYER_LOG": str(tmp / "Player.log"),
               "FAKE_WORKSHOP": str(self.ws), "FAKE_MODS": str(self.mods), "FAKE_RESULT": str(self.result),
               "FAKE_PLAY_SECONDS": "0.3", "WG_GATE_ANSWER": "play"}
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        monkeypatch.delenv("FAKE_EXTRA_DIR", raising=False)
        monkeypatch.delenv("FAKE_TRY_WRITE", raising=False)
        self.cfg = GateConfig(blocklists=[], yara_forge=False, watch_while_playing=False, splash_after=99)

    def game(self) -> steamlib.Game:
        return steamlib.Game(APPID, self.exe_dir / "PlateUp.exe", self.install, self.steamapps, self.buildid, "4",
                             [self.ws])

    def mod(self, item_id: str, files: dict[str, bytes], local: bool = False) -> Path:
        d = (self.mods if local else self.ws) / item_id
        for rel, data in files.items():
            (d / rel).parent.mkdir(parents=True, exist_ok=True)
            (d / rel).write_bytes(data)
        return d

    def run(self, **cfg) -> tuple[int, Gate, dict]:
        self.result.unlink(missing_ok=True)
        c = GateConfig(**{**self.cfg.__dict__, **cfg})
        g = Gate([sys.executable, str(FAKEGAME)], cfg=c, home=self.home, game=self.game())
        rc = g.run()
        rep = json.loads(self.result.read_text()) if self.result.exists() else None
        return rc, g, rep


@pytest.fixture
def lib(tmp_path, monkeypatch):
    return Lib(tmp_path, monkeypatch)


def clean_mod() -> dict[str, bytes]:
    return {"GoodMod.dll": b"MZ" + b"\0" * 62 + b"not really a dll, just bytes" + os.urandom(256),
            "GoodMod.assets": os.urandom(4096), "readme.txt": b"hello"}


def marker_mod() -> dict[str, bytes]:
    return {"EvilMod.dll": f"payload {testdata.MARKER} payload".encode() + os.urandom(64)}


def read_names(rep) -> set[str]:
    return {Path(p).name for p in rep["read"]}


# --- the everyday path --------------------------------------------------------------------------------------------

def test_first_launch_scans_then_next_is_instant(lib):
    lib.mod("1001", clean_mod())
    lib.mod("1002", {"Other.dll": os.urandom(300)})
    rc, g, rep = lib.run()
    assert rc == 0 and g.scanned == 2
    assert read_names(rep) == {"GoodMod.dll", "GoodMod.assets", "Other.dll"}
    t = time.perf_counter()
    rc, g, rep = lib.run()
    assert rc == 0 and g.scanned == 0, "unchanged mods must not be scanned again"
    assert time.perf_counter() - t < 3
    assert read_names(rep) == {"GoodMod.dll", "GoodMod.assets", "Other.dll"}
    (lib.ws / "1001" / "GoodMod.dll").write_bytes(b"after the game: writable again")  # locks were released


def test_only_the_changed_file_is_rescanned(lib):
    lib.mod("1001", {**clean_mod(), "Extra.dll": os.urandom(500)})
    lib.run()
    (lib.ws / "1001" / "Extra.dll").write_bytes(os.urandom(501))
    rc, g, _ = lib.run()
    assert g.scanned == 1
    assert g.results["ws:1599600:1001"].engines == {"scanned": 1, "cached": 3}


def test_same_file_in_two_mods_is_scanned_once(lib):
    shared = os.urandom(2048)
    lib.mod("1001", {"0Harmony.dll": shared})
    lib.mod("1002", {"0Harmony.dll": shared, "Mine.dll": os.urandom(100)})
    _, g, _ = lib.run()
    assert g.results["ws:1599600:1002"].engines == {"scanned": 1, "cached": 1}


def test_files_stay_locked_until_the_game_has_loaded_them(lib, monkeypatch):
    d = lib.mod("1001", clean_mod())
    monkeypatch.setenv("FAKE_TRY_WRITE", str(d / "GoodMod.dll"))
    _, _, rep = lib.run()
    assert rep["errors"]["write_probe"] == "PermissionError", "a mod file could be changed after it was checked"
    assert "GoodMod.dll" in read_names(rep), "the game itself must still be able to read it"


# --- bad mods -----------------------------------------------------------------------------------------------------

def test_malicious_mod_is_quarantined_and_the_rest_still_load(lib):
    lib.mod("1001", clean_mod())
    lib.mod("6666", marker_mod())
    rc, g, rep = lib.run()
    assert rc == 0
    assert not (lib.ws / "6666").exists()
    assert "EvilMod.dll" not in read_names(rep) and "GoodMod.dll" in read_names(rep)
    q = list((lib.home / "quarantine" / str(APPID)).glob("workshop-6666-*"))
    assert q and (q[0] / "EvilMod.dll").exists() and (q[0] / "README_QUARANTINE.txt").exists()
    assert g.st.item("ws:1599600:6666")["status"] == "quarantined"


def test_steam_redownloading_it_is_blocked_without_a_scan(lib):
    files = marker_mod()
    lib.mod("6666", files)
    lib.run()
    lib.mod("6666", files)          # Steam puts it back
    lib.mod("7777", files)          # the same payload under a new Workshop ID
    rc, g, rep = lib.run()
    for key in ("ws:1599600:6666", "ws:1599600:7777"):
        assert any(f.rule == "gate.known_bad" for f in g.results[key].findings), key
    assert not (lib.ws / "6666").exists() and not (lib.ws / "7777").exists()
    assert "EvilMod.dll" not in read_names(rep)


def test_quitting_still_quarantines_malicious_mods_and_starts_nothing(lib, monkeypatch):
    lib.mod("6666", marker_mod())
    monkeypatch.setenv("WG_GATE_ANSWER", "quit")
    rc, _, rep = lib.run()
    assert rc == 0 and rep is None
    assert not (lib.ws / "6666").exists()


@pytest.mark.skipif(not STEALER.exists(), reason="build the fake stealer first (tests/build_fixtures.sh)")
def test_fake_stealer_mod_is_caught(lib):
    lib.mod("9000000001", {"FakeStealerMod.dll": STEALER.read_bytes()})
    _, g, rep = lib.run()
    assert g.results["ws:1599600:9000000001"].verdict == "malicious"
    assert "FakeStealerMod.dll" not in read_names(rep)


def test_local_mods_folder_is_guarded_too(lib):
    lib.mod("LabBuild", {"content/Lab.dll": f"x {testdata.MARKER}".encode()}, local=True)
    lib.mod("Fine", {"Fine.dll": os.urandom(100)}, local=True)
    _, _, rep = lib.run()
    assert not (lib.mods / "LabBuild").exists()
    assert read_names(rep) == {"Fine.dll"}


def test_blocklist_hash_is_blocked(lib, tmp_path):
    files = clean_mod()
    import hashlib
    bl = tmp_path / "blocklist.json"
    bl.write_text(json.dumps({"items": [{"id": "1001", "title": "GoodMod", "reason": "banned by the developer",
                                         "sha256": [hashlib.sha256(files["GoodMod.dll"]).hexdigest()]}]}))
    lib.mod("1001", files)
    _, g, rep = lib.run(blocklists=[str(bl)])
    assert g.results["ws:1599600:1001"].verdict == "malicious"
    assert not (lib.ws / "1001").exists()


# --- suspicious: the player's call, remembered per version -------------------------------------------------------

def suspicious_mod() -> dict[str, bytes]:
    return {"Odd.dll": os.urandom(200), "setup.bat": b"@echo off\r\necho hi\r\n"}


def test_suspicious_allowed_is_remembered_for_that_version(lib, monkeypatch):
    lib.mod("2001", suspicious_mod())
    monkeypatch.setenv("WG_GATE_ANSWER", "allow")
    _, g, rep = lib.run()
    assert g.results["ws:1599600:2001"].verdict == "suspicious"
    assert "Odd.dll" in read_names(rep)
    monkeypatch.setenv("WG_GATE_ANSWER", "quit")   # if it asked again, this would stop the launch
    rc, _, rep = lib.run()
    assert rep is not None and "Odd.dll" in read_names(rep)
    (lib.ws / "2001" / "Odd.dll").write_bytes(os.urandom(201))  # a new version is asked about again
    rc, _, rep = lib.run()
    assert rep is None


def test_suspicious_kept_off_stays_off_when_steam_puts_it_back(lib, monkeypatch):
    files = suspicious_mod()
    lib.mod("2001", files)
    _, _, rep = lib.run()           # answer "play" = play without it
    assert not (lib.ws / "2001").exists() and "Odd.dll" not in read_names(rep)
    lib.mod("2001", files)
    monkeypatch.setenv("WG_GATE_ANSWER", "quit")
    _, _, rep = lib.run()           # not asked again: blocked silently, game starts
    assert rep is not None and not (lib.ws / "2001").exists()


# --- the game's own files -----------------------------------------------------------------------------------------

def test_game_files_changed_without_a_steam_update(lib, monkeypatch):
    g = Gate([sys.executable, str(FAKEGAME)], cfg=lib.cfg, home=lib.home, game=lib.game())
    integrity.full_verify(g.game, g.st, g.adapter.mods_root(g.game))
    (lib.exe_dir / "UnityPlayer.dll").write_bytes(b"MZ tampered" + os.urandom(64))
    monkeypatch.setenv("WG_GATE_ANSWER", "quit")
    rc, g, rep = lib.run()
    assert rep is None and g.gc.status == "changed"
    assert [f.file for f in g.gc.findings if f.rule == "integrity.modified"] == ["PlateUp/UnityPlayer.dll"]
    lib.buildid = "101"             # a real Steam update: re-baselined, nothing to ask
    rc, g, rep = lib.run()
    assert rep is not None and g.gc.status == "baseline"


def test_touched_timestamp_with_same_bytes_is_fine(lib):
    g = Gate([sys.executable, str(FAKEGAME)], cfg=lib.cfg, home=lib.home, game=lib.game())
    integrity.full_verify(g.game, g.st, g.adapter.mods_root(g.game))
    p = lib.exe_dir / "UnityPlayer.dll"
    os.utime(p, (time.time() + 100, time.time() + 100))
    rc, g, rep = lib.run()
    assert rep is not None and g.gc.status == "ok"


def test_dll_hijack_next_to_the_game_is_flagged(lib, monkeypatch):
    (lib.exe_dir / "winhttp.dll").write_bytes(b"MZ proxy" + os.urandom(64))
    monkeypatch.setenv("WG_GATE_ANSWER", "allow")
    rc, g, rep = lib.run()
    assert any(f.rule == "integrity.loader" for f in g.gc.findings) and rep is not None
    monkeypatch.setenv("WG_GATE_ANSWER", "quit")   # approved: not asked again
    rc, g, rep = lib.run()
    assert rep is not None


# --- after launch -------------------------------------------------------------------------------------------------

def test_game_loading_an_unchecked_folder_is_stopped(lib, monkeypatch, tmp_path):
    lib.mod("1001", clean_mod())
    rogue = tmp_path / "elsewhere" / "4242"
    rogue.mkdir(parents=True)
    (rogue / "Rogue.dll").write_bytes(os.urandom(100))
    monkeypatch.setenv("FAKE_EXTRA_DIR", str(rogue))
    monkeypatch.setenv("FAKE_PLAY_SECONDS", "8")
    t = time.perf_counter()
    rc, _, _ = lib.run()
    assert rc == 1 and time.perf_counter() - t < 7, "the game should have been closed straight away"


def test_cant_move_a_bad_mod_starts_with_mods_off(lib):
    d = lib.mod("6666", {**marker_mod(), "notes.txt": b"x"})
    holder = open(d / "notes.txt", "rb")  # another program has the folder busy
    try:
        _, _, rep = lib.run()
    finally:
        holder.close()
    assert "-nomods" in rep["argv"]


def test_update_downloaded_mid_game_is_scanned_and_quarantined(lib, monkeypatch):
    lib.mod("1001", clean_mod())
    monkeypatch.setattr(runner, "WATCH_SECONDS", 0.2)
    monkeypatch.setenv("FAKE_PLAY_SECONDS", "4")

    def steam_updates_it():
        time.sleep(1.5)
        (lib.ws / "1001" / "Update.dll").write_bytes(f"v2 {testdata.MARKER}".encode())

    threading.Thread(target=steam_updates_it, daemon=True).start()
    rc, g, _ = lib.run(watch_while_playing=True)
    assert g.st.item("ws:1599600:1001")["status"] == "quarantined"
    assert not (lib.ws / "1001").exists()


# --- pieces -------------------------------------------------------------------------------------------------------

def test_defender_report_parsing():
    out = ("Scan starting...\nScan finished.\nScanning C:\\x found 1 threats.\n\n"
           "<===========================LIST OF DETECTED THREATS==========================>\n"
           "----------------------------- Threat information ------------------------------\n"
           "Threat                  : Virus:DOS/EICAR_Test_File\nResources               : 1 total\n"
           "    file                : C:\\x\\a.zip->b.txt\n")
    assert defender.parse(out) == [("Virus:DOS/EICAR_Test_File", "C:\\x\\a.zip")]


@pytest.mark.skipif(defender.find() is None, reason="no Microsoft Defender")
def test_defender_runs_clean_folder(tmp_path):
    (tmp_path / "a.txt").write_text("hello")
    d = defender.Defender(defender.find())
    assert d.result(d.start(tmp_path))[0] == "clean"


LOCALCONFIG = """"UserLocalConfigStore"
{
\t"Software"
\t{
\t\t"Valve"
\t\t{
\t\t\t"Steam"
\t\t\t{
\t\t\t\t"apps"
\t\t\t\t{
\t\t\t\t\t"1599600"
\t\t\t\t\t{
\t\t\t\t\t\t"LastPlayed"\t\t"1"
\t\t\t\t\t}
\t\t\t\t}
\t\t\t}
\t\t}
\t}
\t"friends"\t\t"x"
}
"""


def test_launch_options_edit_only_that_value(tmp_path):
    lc = tmp_path / "localconfig.vdf"
    lc.write_text(LOCALCONFIG, encoding="utf-8")
    v = '"C:\\py\\pythonw.exe" "Y:\\wg\\gate.pyw" %command%'
    assert steamlib.set_launch_options(lc, APPID, v) == ""
    assert steamlib.get_launch_options(lc, APPID) == v
    assert steamlib.get_ci(steamlib.parse_vdf(lc.read_text()), "UserLocalConfigStore", "friends") == "x"
    assert steamlib.set_launch_options(lc, APPID, "-x") == v
    assert steamlib.get_launch_options(lc, APPID) == "-x"
    steamlib.set_launch_options(lc, APPID, None)
    assert steamlib.get_launch_options(lc, APPID) == ""
    assert steamlib.set_launch_options(lc, 42, "-y") == ""    # an app with no block yet
    assert steamlib.get_launch_options(lc, 42) == "-y"
    assert steamlib.get_ci(steamlib.parse_vdf(lc.read_text()), "UserLocalConfigStore", "Software", "Valve",
                           "Steam", "apps", "1599600", "LastPlayed") == "1"


def test_guard_mode_catches_a_new_mod_while_the_game_is_closed(lib, monkeypatch):
    from workshopguard.gate.__main__ import _Forever
    lib.mod("1001", clean_mod())
    monkeypatch.setattr(runner, "WATCH_SECONDS", 0.2)
    cfg = GateConfig(**{**lib.cfg.__dict__, "verify_game_files": False, "watch_while_playing": True})
    g = Gate([sys.executable, str(FAKEGAME)], cfg=cfg, home=lib.home, game=lib.game())
    g.scan(g.check())
    g.release()
    stop = threading.Event()
    t = threading.Thread(target=g.watch, args=(_Forever(stop),), daemon=True)
    t.start()
    lib.mod("6666", marker_mod())   # Steam installs a new subscription
    for _ in range(50):
        if not (lib.ws / "6666").exists():
            break
        time.sleep(0.1)
    stop.set()
    t.join(5)
    assert not (lib.ws / "6666").exists() and g.st.item("ws:1599600:6666")["status"] == "quarantined"


def test_file_the_antivirus_refuses_to_open_counts_as_malicious(lib):
    # Microsoft's harmless AMSI test string (reversed here so this file isn't flagged); Defender's real-time
    # protection refuses to let anything read a file containing it, which the gate must not shrug off as "unreadable"
    sample = "6831c4841ca0-0478-9334-b168-ec3c27e7 :elpmaS tseT ISMA"[::-1].encode("utf-16-le")
    d = lib.mod("6667", {"notes.txt": sample})
    try:
        (d / "notes.txt").read_bytes()
        pytest.skip("no real-time antivirus blocking reads on this PC")
    except OSError:
        pass
    _, g, _ = lib.run()
    res = g.results["ws:1599600:6667"]
    assert res.verdict == "malicious" and any(f.rule == "antivirus.blocked_read" for f in res.findings)


def test_theme_folder_replaces_every_word_and_colour(tmp_path):
    from workshopguard.gate.ui import UI, load_theme
    (tmp_path / "theme.json").write_text(json.dumps({
        "product": "Kitchen Mod Check", "short": "Mod Check", "logo": "logo.png",
        "colors": {"bg": "#101010"},
        "strings": {"title_stopped_one": "{short} kept a bad mod out of {game}", "quit": "Leave", "odd": "{nope}"},
    }), encoding="utf-8")
    t = load_theme(tmp_path)
    assert t.logo == tmp_path / "logo.png" and t.c("bg") == "#101010" and t.c("card") == "#1e2a38"
    ui = UI("PlateUp!", theme=t)
    assert ui.brand == "Kitchen Mod Check"
    assert ui.s("title_stopped_one") == "Mod Check kept a bad mod out of PlateUp!"
    assert ui.s("quit") == "Leave" and ui.s("play") == "Play"          # unset strings fall back
    assert ui.s("odd") == "{nope}"                                     # an unknown placeholder never crashes
    assert "WorkshopGuard" not in ui.s("closed_title") and "WorkshopGuard" not in ui.s("error_title")
