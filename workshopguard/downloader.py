"""Downloading Workshop items with SteamCMD.

Some games (e.g. Black Ops III) let anyone download their Workshop items anonymously. Others (e.g. PlateUp!) only
serve them to an account that owns the game. We try anonymous first, remember what worked per game, and fall back to
the account from STEAM_USERNAME, whose login SteamCMD caches after `workshopguard login`.

Files are only ever written to disk here. Nothing downloaded is executed.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

STEAMCMD = os.environ.get("STEAMCMD", "/opt/steamcmd/steamcmd.sh")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
OK_RE = re.compile(r'Success\. Downloaded item (\d+) to "([^"]+)"')
FAIL_RE = re.compile(r"ERROR! (?:Download item|Timeout downloading item) (\d+)(?: failed \(([^)]*)\))?")
LOGIN_PROBLEMS = (
    "Cached credentials not found", "password:", "Invalid Password", "Login Failure", "Steam Guard code",
    "Two-factor code", "Rate Limit Exceeded", "FAILED (Invalid Login Auth Code)", "Account Logon Denied",
)


class LoginRequired(RuntimeError):
    pass


@dataclass
class DownloadResult:
    item_id: str
    path: Path | None
    error: str = ""


def _run(args: list[str], timeout: int) -> str:
    log.debug("steamcmd %s", " ".join(a if "login" not in a else a for a in args))
    try:
        p = subprocess.run(
            [STEAMCMD, *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout, text=True, errors="replace",
        )
        out = p.stdout
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        out += "\nERROR! steamcmd timed out"
    return ANSI_RE.sub("", out)


class Downloader:
    def __init__(self, install_dir: Path, steam_username: str = ""):
        self.install_dir = install_dir
        self.username = steam_username
        # appid -> True (anonymous works) / False (needs account); filled lazily, persisted by the caller
        self.anon_ok: dict[int, bool] = {}

    def content_dir(self, appid: int, item_id: str) -> Path:
        return self.install_dir / "steamapps" / "workshop" / "content" / str(appid) / item_id

    def _download(self, appid: int, ids: list[str], login: list[str], timeout: int) -> dict[str, DownloadResult]:
        args = ["+force_install_dir", str(self.install_dir), *login]
        for i in ids:
            args += ["+workshop_download_item", str(appid), i, "validate"]
        args.append("+quit")
        out = _run(args, timeout)
        if any(p in out for p in LOGIN_PROBLEMS) and login[1] != "anonymous":
            raise LoginRequired(
                f"SteamCMD could not log in as '{self.username}' with cached credentials. "
                "Run: docker compose run --rm guard login")
        results: dict[str, DownloadResult] = {}
        for m in OK_RE.finditer(out):
            path = Path(m.group(2))
            if path.is_file():  # legacy items (older Source games) come back as one "<id>_legacy.bin" file
                path = path.parent
            results[m.group(1)] = DownloadResult(m.group(1), path)
        for m in FAIL_RE.finditer(out):
            if m.group(1) not in results:
                results[m.group(1)] = DownloadResult(m.group(1), None, m.group(2) or "Timeout")
        for i in ids:
            if i not in results:
                tail = " | ".join(out.strip().splitlines()[-3:])
                results[i] = DownloadResult(i, None, f"no result from steamcmd: {tail[:300]}")
        return results

    def download(self, appid: int, item_ids: list[str], size_hint: int = 0) -> dict[str, DownloadResult]:
        """Download items for one game. Retries timeouts (SteamCMD resumes big items)."""
        timeout = 600 + size_hint // (2 * 1024 * 1024)  # ~2 MB/s floor for big items
        pending = list(item_ids)
        results: dict[str, DownloadResult] = {}
        for attempt in range(3):
            if not pending:
                break
            login = self._login_args(appid)
            res = self._download(appid, pending, login, timeout)
            if self.anon_ok.get(appid) is None and login[1] == "anonymous":
                any_ok = any(r.path for r in res.values())
                failures = [r for r in res.values() if r.error == "Failure"]
                if any_ok:
                    self.anon_ok[appid] = True
                elif failures and self.username:
                    log.info("App %s refuses anonymous Workshop downloads; using account %s", appid, self.username)
                    self.anon_ok[appid] = False
                    continue
                elif failures:
                    self.anon_ok[appid] = False
                    for r in failures:
                        r.error = ("This game only serves Workshop files to an account that owns it. Set "
                                   "STEAM_USERNAME and run: docker compose run --rm guard login")
            if login[1] != "anonymous":
                for r in res.values():
                    if r.error == "Failure":
                        r.error = (f"Steam refused the download for account '{self.username}'. That account probably "
                                   "doesn't own this game, which it needs to for this game's Workshop.")
            results.update(res)
            pending = [i for i, r in res.items() if not r.path and "Timeout" in r.error]
        return results

    def _login_args(self, appid: int) -> list[str]:
        if self.anon_ok.get(appid) is False and self.username:
            return ["+login", self.username]
        return ["+login", "anonymous"]

    def cleanup(self, appid: int, item_id: str) -> None:
        shutil.rmtree(self.content_dir(appid, item_id), ignore_errors=True)

    def reset(self, appid: int | None = None) -> None:
        """Forget SteamCMD's workshop state. Its appworkshop_<appid>.acf remembers every item ever requested and
        resumes unfinished ones on the next run, which would pull in items we decided to skip."""
        ws = self.install_dir / "steamapps" / "workshop"
        apps = [str(appid)] if appid else ["*"]
        for a in apps:
            for f in ws.glob(f"appworkshop_{a}.acf"):
                f.unlink(missing_ok=True)
            for sub in ("content", "downloads", "temp"):
                for d in (ws / sub).glob(a):
                    shutil.rmtree(d, ignore_errors=True)


def interactive_login(username: str) -> int:
    """Log in once with password + Steam Guard so SteamCMD caches a token in the data volume."""
    if not username:
        print("Set STEAM_USERNAME in .env first (an account that owns the games you want to scan).")
        return 2
    print(f"Logging in to Steam as {username}. SteamCMD will ask for the password and Steam Guard code.")
    print("Your password goes straight to SteamCMD; WorkshopGuard never stores it. Only Steam's login token is kept.")
    return subprocess.call([STEAMCMD, "+login", username, "+quit"])
