"""Checks every text/background pair the windows use against WCAG AA (4.5:1 for text).

    python branding/plateup/tools/check_contrast.py        (exit code 1 if any text pair fails)

Change a colour in theme.json, run this again. Non-text pairs (stripes, progress bar) are shown against 3:1.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
C = json.loads((ROOT / "theme.json").read_text(encoding="utf-8"))["colors"]

# (foreground, background, where it appears)
TEXT = [
    ("text", "bg", "titles, alert text, progress heading"),
    ("dim", "bg", "subtitle, brand line, quarantine line"),
    ("text", "card", "mod titles and reasons on cards"),
    ("dim", "card", "where-line and notes on cards"),
    ("link", "card", "'Workshop page' link"),
    ("badge_text", "malicious", "MALICIOUS badge"),
    ("badge_text", "suspicious", "SUSPICIOUS badge"),
    ("badge_text", "game", "GAME FILES badge"),
    ("primary_text", "primary", "Play button"),
    ("primary_text", "primary_hover", "Play button, hovered"),
    ("secondary_text", "secondary", "Quit / Repair buttons"),
    ("secondary_text", "secondary_hover", "Quit / Repair, hovered"),
]
SHAPES = [
    ("malicious", "card", "malicious stripe"),
    ("suspicious", "card", "suspicious stripe"),
    ("game", "card", "game-files stripe"),
    ("progress", "progress_trough", "progress bar"),
    ("primary", "bg", "Play button edge"),
]


def lum(h: str) -> float:
    h = h.lstrip("#")
    out = []
    for i in (0, 2, 4):
        v = int(h[i:i + 2], 16) / 255
        out.append(v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4)
    return 0.2126 * out[0] + 0.7152 * out[1] + 0.0722 * out[2]


def ratio(a: str, b: str) -> float:
    la, lb = sorted((lum(a), lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def main() -> int:
    bad = 0
    print(f"{'pair':34} {'colours':19} ratio  need")
    for group, need in ((TEXT, 4.5), (SHAPES, 3.0)):
        for fg, bg, where in group:
            r = ratio(C[fg], C[bg])
            ok = r >= need
            bad += (not ok) and need == 4.5
            print(f"{fg + ' on ' + bg:34} {C[fg]} on {C[bg]} {r:5.2f}  {need}  {'ok ' if ok else 'LOW'} {where}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
