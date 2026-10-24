"""Steam on this PC: libraries, app manifests, Workshop folders, and the per-game launch options."""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

_TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"|(\{)|(\})|//[^\n]*')


def _unescape(s: str) -> str:
    return s.replace('\\"', '"').replace("\\\\", "\\")


def vdf_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def parse_vdf(text: str) -> dict:
    """Valve KeyValues text (.vdf/.acf) as nested dicts. Keys are kept as written; use get_ci() to look them up."""
    root: dict = {}
    stack = [root]
    key = None
    for m in _TOKEN.finditer(text):
        s, opened, closed = m.group(1), m.group(2), m.group(3)
        if opened:
            child: dict = {}
            stack[-1][key if key is not None else ""] = child
            stack.append(child)
            key = None
        elif closed:
            if len(stack) > 1:
                stack.pop()
            key = None
        elif s is not None:
            if key is None:
                key = _unescape(s)
            else:
                stack[-1][key] = _unescape(s)
                key = None
    return root


def get_ci(d: dict, *path: str):
    for p in path:
        if not isinstance(d, dict):
            return None
        d = next((v for k, v in d.items() if k.lower() == p.lower()), None)
    return d


def steam_root() -> Path | None:
    env = os.environ.get("WG_STEAM_ROOT")
    if env:
        return Path(env)
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam") as k:
            return Path(winreg.QueryValueEx(k, "SteamPath")[0])
    except OSError:
        pass
    for p in (Path(r"C:\Program Files (x86)\Steam"), Path.home() / ".steam" / "steam"):
        if p.is_dir():
            return p
    return None


@dataclass
class Game:
    appid: int
    exe: Path                    # what Steam asked us to start
    install_dir: Path            # steamapps/common/<installdir>
    steamapps: Path              # the library's steamapps folder
    buildid: str = ""
    state_flags: str = ""
    workshop_dirs: list[Path] = field(default_factory=list)  # every library's workshop/content/<appid>

    @property
    def updating(self) -> bool:
        return self.state_flags not in ("", "4")  # 4 = fully installed


def libraries(root: Path | None) -> list[Path]:
    """Every library's steamapps folder."""
    out: list[Path] = []
    if root is None:
        return out
    f = root / "steamapps" / "libraryfolders.vdf"
    try:
        data = get_ci(parse_vdf(f.read_text(encoding="utf-8", errors="replace")), "libraryfolders") or {}
        for v in data.values():
            if isinstance(v, dict) and v.get("path"):
                out.append(Path(v["path"]) / "steamapps")
    except OSError:
        pass
    if (root / "steamapps").is_dir() and not any(_same(p, root / "steamapps") for p in out):
        out.append(root / "steamapps")
    return out


def _same(a: Path, b: Path) -> bool:
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def find_game(cmd: list[str], appid: int | None = None) -> Game:
    """Work out which game `cmd` starts: the exe sits somewhere under <library>/steamapps/common/<installdir>."""
    exe = Path(cmd[0]).resolve()
    parts = exe.parts
    idx = next((i for i in range(len(parts) - 2, 0, -1)
                if parts[i].lower() == "common" and parts[i - 1].lower() == "steamapps"), None)
    if idx is None:
        raise RuntimeError(f"{exe} isn't inside a Steam library (…/steamapps/common/<game>/)")
    steamapps = Path(*parts[:idx])
    install_dir = Path(*parts[:idx + 2])
    manifest = None
    for acf in sorted(steamapps.glob("appmanifest_*.acf")):
        try:
            st = get_ci(parse_vdf(acf.read_text(encoding="utf-8", errors="replace")), "AppState") or {}
        except OSError:
            continue
        if appid and str(st.get("appid")) == str(appid) or (
                not appid and (st.get("installdir") or "").lower() == install_dir.name.lower()):
            manifest = st
            break
    if manifest is None and not appid:
        raise RuntimeError(f"No Steam app manifest in {steamapps} for {install_dir.name}")
    g = Game(int(appid or manifest["appid"]), exe, install_dir, steamapps,
             (manifest or {}).get("buildid", ""), (manifest or {}).get("StateFlags", ""))
    seen = set()
    for lib in [steamapps] + libraries(steam_root()):
        d = lib / "workshop" / "content" / str(g.appid)
        key = os.path.normcase(os.path.abspath(d))
        if key not in seen and d.is_dir():
            seen.add(key)
            g.workshop_dirs.append(d)
    return g


def locate(appid: int, exe_rel: str | None = None) -> Game:
    """Find an installed game by app ID (for commands run outside Steam, like `scan`)."""
    for lib in libraries(steam_root()):
        acf = lib / f"appmanifest_{appid}.acf"
        if not acf.is_file():
            continue
        st = get_ci(parse_vdf(acf.read_text(encoding="utf-8", errors="replace")), "AppState") or {}
        install = lib / "common" / st.get("installdir", "")
        exe = install / exe_rel if exe_rel else next(
            (p for p in sorted(install.glob("*.exe")) if "crash" not in p.name.lower()), install / "game.exe")
        return find_game([str(exe)], appid)
    raise RuntimeError(f"App {appid} isn't installed in any Steam library on this PC")


# --- launch options ----------------------------------------------------------------------------------------------

def steam_running() -> bool:
    try:
        out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq steam.exe", "/NH"], capture_output=True, text=True,
                             timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
        return "steam.exe" in out.lower()
    except (OSError, subprocess.SubprocessError):
        return False


def localconfigs(root: Path) -> list[Path]:
    return sorted((root / "userdata").glob("*/config/localconfig.vdf"))


def set_launch_options(localconfig: Path, appid: int, value: str | None) -> str:
    """Set (or with None, clear) an app's launch options in localconfig.vdf, editing only that one value so the
    rest of the file is byte-for-byte untouched. Steam must be closed, or it overwrites the file when it exits.
    Returns the previous value."""
    text = localconfig.read_text(encoding="utf-8")
    toks = [(m.start(), m.end(), m) for m in _TOKEN.finditer(text) if not m.group(0).startswith("//")]

    def block(start: int, end: int, name: str) -> tuple[int, int] | None:
        """Find `"name" { ... }` directly inside tokens[start:end]; return its inner token range."""
        i, depth = start, 0
        while i < end:
            m = toks[i][2]
            if m.group(2):
                depth += 1
            elif m.group(3):
                depth -= 1
            elif depth == 0 and m.group(1) is not None and i + 1 < end and toks[i + 1][2].group(2):
                j, d = i + 1, 0
                while j < end:
                    if toks[j][2].group(2):
                        d += 1
                    elif toks[j][2].group(3):
                        d -= 1
                        if d == 0:
                            break
                    j += 1
                if _unescape(m.group(1)).lower() == name.lower():
                    return i + 2, j
                i = j
            i += 1
        return None

    rng: tuple[int, int] | None = (0, len(toks))
    for name in ("UserLocalConfigStore", "Software", "Valve", "Steam", "apps"):
        rng = block(*rng, name)
        if rng is None:
            raise RuntimeError(f"localconfig.vdf has no {name} section")
    app = block(*rng, str(appid))
    escaped = vdf_escape(value) if value is not None else None
    if app is None:
        if value is None:
            return ""
        pos = toks[rng[1]][0]  # the apps block's closing brace
        text = (text[:pos] + f'\t"{appid}"\n\t\t\t\t\t{{\n\t\t\t\t\t\t"LaunchOptions"\t\t"{escaped}"\n\t\t\t\t\t}}\n'
                + "\t\t\t\t" + text[pos:])
        localconfig.write_text(text, encoding="utf-8")
        return ""
    i, depth = app[0], 0
    while i < app[1]:
        m = toks[i][2]
        if m.group(2):
            depth += 1
        elif m.group(3):
            depth -= 1
        elif depth == 0 and m.group(1) is not None and i + 1 < app[1] and toks[i + 1][2].group(1) is not None:
            if _unescape(m.group(1)).lower() == "launchoptions":
                old = _unescape(toks[i + 1][2].group(1))
                if value is None:
                    line_start = text.rfind("\n", 0, toks[i][0]) + 1
                    line_end = text.find("\n", toks[i + 1][1])
                    text = text[:line_start] + text[line_end + 1 if line_end >= 0 else len(text):]
                else:
                    text = text[:toks[i + 1][0]] + f'"{escaped}"' + text[toks[i + 1][1]:]
                localconfig.write_text(text, encoding="utf-8")
                return old
            i += 1
        i += 1
    if value is not None:
        pos = toks[app[1]][0]  # the app block's closing brace
        line_start = text.rfind("\n", 0, pos) + 1
        indent = text[line_start:pos]
        text = text[:line_start] + f'{indent}\t"LaunchOptions"\t\t"{escaped}"\n' + text[line_start:]
        localconfig.write_text(text, encoding="utf-8")
    return ""


def get_launch_options(localconfig: Path, appid: int) -> str:
    data = parse_vdf(localconfig.read_text(encoding="utf-8", errors="replace"))
    return get_ci(data, "UserLocalConfigStore", "Software", "Valve", "Steam", "apps", str(appid),
                  "LaunchOptions") or ""
