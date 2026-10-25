"""Opens the real launch-gate windows with this theme, made-up example mods, and saves a picture of each to preview/.

Windows only. Nothing is scanned, moved or started; each window closes itself after its picture is taken.

    python branding/plateup/tools/preview_windows.py
"""

from __future__ import annotations

import ctypes
import sys
import time
from ctypes import wintypes
from pathlib import Path

from PIL import Image

THEME_DIR = Path(__file__).resolve().parents[1]
REPO = THEME_DIR.parents[1]
OUT = THEME_DIR / "preview"
sys.path.insert(0, str(REPO))

from workshopguard.gate import ui as U  # noqa: E402

WS = r"C:\Program Files (x86)\Steam\steamapps\workshop\content\1599600"
QUARANTINE = Path(r"C:\Users\you\AppData\Local\ModCheck\quarantine\1599600")   # example paths for the pictures


class _BIH(ctypes.Structure):
    _fields_ = [("biSize", ctypes.c_uint32), ("biWidth", ctypes.c_int32), ("biHeight", ctypes.c_int32),
                ("biPlanes", ctypes.c_uint16), ("biBitCount", ctypes.c_uint16), ("biCompression", ctypes.c_uint32),
                ("biSizeImage", ctypes.c_uint32), ("x", ctypes.c_int32), ("y", ctypes.c_int32),
                ("used", ctypes.c_uint32), ("important", ctypes.c_uint32)]


def snap(win, name: str):
    """PrintWindow, so it works even when the window is covered (or the screen is locked)."""
    win.update()
    win.after(250)
    win.update()
    u, g = ctypes.windll.user32, ctypes.windll.gdi32
    hwnd = win.winfo_id() if win.overrideredirect() else (u.GetParent(win.winfo_id()) or win.winfo_id())
    r = wintypes.RECT()
    u.GetWindowRect(hwnd, ctypes.byref(r))
    w, h = r.right - r.left, r.bottom - r.top
    hdc = u.GetWindowDC(hwnd)
    mdc = g.CreateCompatibleDC(hdc)
    bmp = g.CreateCompatibleBitmap(hdc, w, h)
    g.SelectObject(mdc, bmp)
    u.PrintWindow(hwnd, mdc, 2)
    buf = ctypes.create_string_buffer(w * h * 4)
    g.GetDIBits(mdc, bmp, 0, h, buf, ctypes.byref(_BIH(ctypes.sizeof(_BIH), w, -h, 1, 32, 0, 0, 0, 0, 0, 0)), 0)
    Image.frombuffer("RGB", (w, h), buf, "raw", "BGRX", 0, 1).save(OUT / f"{name}.png", optimize=True)
    g.DeleteObject(bmp)
    g.DeleteDC(mdc)
    u.ReleaseDC(hwnd, hdc)


def main():
    OUT.mkdir(exist_ok=True)
    ui = U.UI("PlateUp!", 0.0, THEME_DIR)
    s = ui.s
    root = ui._tk()
    names = iter(["dialog", "alert-update", "alert-error", "dialog-game-files"])

    def take(win):
        snap(win, next(names))
        win.destroy()

    root.wait_window = take
    ui.ask([
        U.Problem("1", "Golden Spatula Pack (example)", f"{s('workshop_item', id=9000000001)} · {WS}\\9000000001",
                  "malicious",
                  [("Microsoft Defender: Trojan:MSIL/Stealer (example)", "Spatula.dll"),
                   ("Reads account secrets and can send them over the internet (stealer pattern)", "Spatula.dll"),
                   ("Contains a Discord webhook (common exfiltration)", "Spatula.dll")],
                  note=s("note_malicious_workshop"), link="https://example.invalid"),
        U.Problem("2", "Odd Oven (example)", f"{s('workshop_item', id=9000000002)} · {WS}\\9000000002", "suspicious",
                  [("'.bat' files can run code on your PC; PlateUp! items don't need them", "setup.bat")],
                  can_allow=True, note=s("note_suspicious"), link="https://example.invalid"),
    ], QUARANTINE)
    ui.alert(s("update_title", mod="Golden Spatula Pack (example)"),
             s("update_body", reasons="•  Reads account secrets and can send them over the internet"))
    ui.alert(s("error_title"), s("error_body", error="Steam's library folders couldn't be read.",
                                 log=r"C:\Users\you\AppData\Local\ModCheck\check.log"),
             (s("error_quit"), s("error_play_nomods")), default=0)   # as the gate shows it: quitting is the safe default
    ui._header = None   # the game-files case, shown with the logo instead of the header
    ui.ask([U.Problem("g", s("game_files_title"), r"C:\Program Files (x86)\Steam\steamapps\common\PlateUp", "game",
                      [("A file the game doesn't ship with: winhttp.dll", "winhttp.dll")], note=s("note_game"))],
           QUARANTINE)

    # the progress window: grab it while the fake check runs
    def grab_progress():
        for w in root.winfo_children():
            snap(w, "progress")

    root.after(700, grab_progress)

    def work(progress):
        for i in range(30):
            progress("Odd Oven (example) · setup.bat", i / 30)
            time.sleep(0.05)

    ui.run(work, s("checking_many", n=3))
    ui.close()
    print("wrote", *sorted(p.name for p in OUT.glob("*.png")))


if __name__ == "__main__":
    main()
