"""Per-game profiles.

A profile says what a normal Workshop item for that game looks like, so anything outside it stands out. Users pick
games by alias or app ID; unknown app IDs get the generic profile.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Extensions that can run code on Windows / Linux if a player double-clicks them or a loader picks them up.
EXECUTABLE_EXTS = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".hta", ".lnk", ".msi", ".msp", ".jar", ".reg", ".cpl", ".sh", ".appimage", ".elf", ".so", ".dylib", ".url",
    ".iso", ".img", ".vhd", ".vhdx",
}


@dataclass
class GameProfile:
    appid: int
    name: str
    aliases: tuple[str, ...] = ()
    # File extensions a normal item contains. Anything else is reported (low severity unless it's executable).
    expected_exts: set[str] = field(default_factory=set)
    # Extensions that are normal *code* for this game (scanned hard, but not flagged just for existing).
    code_exts: set[str] = field(default_factory=set)
    # Whether native/managed DLLs are a normal part of mods for this game.
    dlls_expected: bool = False
    notes: str = ""


_COMMON_ASSETS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tga", ".dds", ".webp", ".txt", ".md", ".json", ".xml", ".ini",
    ".cfg", ".yml", ".yaml", ".csv", ".wav", ".ogg", ".mp3", ".flac", ".mp4", ".webm", ".ttf", ".otf", ".vdf", "",
}

PROFILES: dict[int, GameProfile] = {}


def _add(p: GameProfile) -> None:
    PROFILES[p.appid] = p


_add(GameProfile(
    1599600, "PlateUp!", ("plateup",),
    expected_exts=_COMMON_ASSETS | {".dll", ".pdb", ".assets", ".bundle", ".assetbundle", ".manifest", ".mdb"},
    code_exts={".dll"}, dlls_expected=True,
    notes="Unity/C# mods: a .NET DLL plus asset bundles. Oct 2026 incident used a delayed payload in mod code.",
))
_add(GameProfile(
    311210, "Call of Duty: Black Ops III", ("bo3", "blackops3", "black-ops-3", "t7"),
    expected_exts=_COMMON_ASSETS | {".ff", ".xpak", ".sabl", ".sabs", ".fd", ".fs", ".zip", ".gsc", ".csc", ".lua",
                                    ".tml", ".ddl", ".str", ".gdt", ".csv", ".bin"},
    code_exts={".gsc", ".csc", ".lua"}, dlls_expected=False,
    notes="Maps/mods are fastfiles (.ff) + sound banks. A DLL or EXE in a BO3 item is never needed by the game.",
))
_add(GameProfile(
    1118200, "People Playground", ("peopleplayground", "pplg"),
    expected_exts=_COMMON_ASSETS | {".cs", ".mod"},
    code_exts={".cs"},
    notes="Mods are C# source compiled by the game at load. Hit by Workshop malware twice in 2026.",
))
_add(GameProfile(
    108600, "Project Zomboid", ("zomboid", "pz", "projectzomboid"),
    expected_exts=_COMMON_ASSETS | {".lua", ".pack", ".tiles", ".bank", ".x", ".fbx", ".lotheader", ".bin"},
    code_exts={".lua"},
))
_add(GameProfile(
    4000, "Garry's Mod", ("gmod", "garrysmod"),
    expected_exts=_COMMON_ASSETS | {".gma", ".lua", ".mdl", ".vtx", ".vvd", ".phy", ".vmt", ".vtf", ".bsp", ".pcf"},
    code_exts={".lua"},
))
_add(GameProfile(
    294100, "RimWorld", ("rimworld",),
    expected_exts=_COMMON_ASSETS | {".dll", ".pdb", ".xml"}, code_exts={".dll"}, dlls_expected=True,
))
_add(GameProfile(
    286160, "Tabletop Simulator", ("tts", "tabletopsimulator"),
    expected_exts=_COMMON_ASSETS | {".lua", ".obj", ".unity3d", ".pdf"}, code_exts={".lua"},
))
_add(GameProfile(
    255710, "Cities: Skylines", ("cities", "citiesskylines", "cs1"),
    expected_exts=_COMMON_ASSETS | {".dll", ".crp", ".pdb"}, code_exts={".dll"}, dlls_expected=True,
))
_add(GameProfile(
    431960, "Wallpaper Engine", ("wallpaperengine", "wallpaper"),
    expected_exts=_COMMON_ASSETS | {".pkg", ".html", ".css", ".js", ".mpkg", ".tex"},
    code_exts={".js", ".html"},
    notes=".js/.html are normal web wallpapers here, so they aren't flagged as executables.",
))
_add(GameProfile(
    262060, "Darkest Dungeon", ("darkestdungeon",), expected_exts=_COMMON_ASSETS | {".darkest", ".layout", ".bank"},
))


def resolve(token: str) -> GameProfile:
    """Turn 'plateup', '1599600' or a Steam store URL into a profile."""
    t = token.strip().lower()
    if "/app/" in t:  # https://store.steampowered.com/app/1599600/PlateUp/
        t = t.split("/app/")[1].split("/")[0]
    if t.isdigit():
        appid = int(t)
        return PROFILES.get(appid) or GameProfile(appid, f"App {appid}", expected_exts=set(_COMMON_ASSETS))
    for p in PROFILES.values():
        if t in p.aliases or t == p.name.lower():
            return p
    known = ", ".join(sorted(a for p in PROFILES.values() for a in p.aliases[:1]))
    raise ValueError(f"Unknown game '{token}'. Use a Steam app ID (any game works) or one of: {known}")


def profile_for(appid: int) -> GameProfile:
    return resolve(str(appid))
