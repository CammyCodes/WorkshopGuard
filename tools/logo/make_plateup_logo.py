"""The PlateUp! edition of WorkshopGuard's logo: the same pixel shield and squashed bug, wearing a chef's hat, on warm
kitchen colours. Our own art (no PlateUp! assets), drawn with make_logo.py's method.

    python tools/logo/make_plateup_logo.py

Outputs (docs/plateup/): logo.png 512x512, logo-32.png, banner.png 1280x400
"""
import os

from PIL import Image, ImageDraw

import make_logo as base

N = base.N
base.C.update({
    "H": (255, 255, 255),     # hat
    "h": (222, 214, 204),     # hat shade
})
base.BG = ((255, 241, 218), (250, 204, 148))
base.FONT.update({
    "E": ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
    "F": ["11111", "10000", "10000", "11110", "10000", "10000", "10000"],
    "L": ["10000", "10000", "10000", "10000", "10000", "10000", "11111"],
    "T": ["11111", "00100", "00100", "00100", "00100", "00100", "00100"],
    "!": ["1", "1", "1", "1", "1", "0", "1"],
})
WORDMARK = [("WORKSHOP", 10, (70, 40, 25)), ("GUARD", 10, (226, 112, 36))]
SUB = ("FOR PLATEUP!", 5, (70, 40, 25))
UNDERLINE = (226, 112, 36)
SCALE = 0.78  # the shield shrinks a little to make room for the hat
TOP = 10.2    # where the shield's top edge now sits
shield = base.sample


def sample(x, y):
    # Chef's hat: a pleated band under three puffs, with a dark line where it sits on the shield.
    if 10.0 <= y < 11.0 and 10.6 <= x <= 20.4:
        return "K"
    if 6.2 <= y < 10.0 and 11.0 <= x <= 20.0:
        if any(abs(x - px) < 0.45 for px in (13.5, 15.5, 17.5)) and y > 7.0:
            return "h"
        return "h" if y > 9.1 else "H"
    puffs = ((11.8, 4.6, 2.7), (15.5, 3.2, 3.0), (19.2, 4.6, 2.7))
    for cx, cy, r in puffs:
        if base.ellipse(x, y, cx, cy, r, r * 0.92):
            if y > 6.2:
                return "h"
            if any(base.ellipse(x, y, ox, oy, orr, orr * 0.92) for ox, oy, orr in puffs if ox != cx) and y > 4.6:
                return "h"   # the crease between two puffs
            return "H"
    # The bug stays full size (scaled down it loses its eyes and legs), nudged to sit on the smaller shield.
    ox, oy = x + 0.6, y - 1.3
    bug = shield(ox, oy)
    if bug in ("R", "r") or (bug == "W" and base.ellipse(ox, oy, 25.0, 26.0, 3.2, 2.4)):
        return bug
    # Everything else is the original logo, scaled down under the hat.
    v = shield(15.5 + (x - 15.5) / SCALE, 3.5 + (y - TOP) / SCALE)
    return "." if v in ("R", "r") else v


def main():
    base.sample = sample            # base.pixel() samples through this
    g = base.outline(base.grid())
    out = os.path.join(base.ROOT, "docs", "plateup")
    os.makedirs(out, exist_ok=True)
    base.to_image(g, 1).save(os.path.join(out, "logo-32.png"))

    logo = base.backdrop(512, 512)
    mask = Image.new("L", (512, 512), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, 511, 511], radius=96, fill=255)
    sprite = base.to_image(g, 14)
    logo.alpha_composite(sprite, ((512 - sprite.width) // 2, (512 - sprite.height) // 2))
    logo.putalpha(mask)
    logo.save(os.path.join(out, "logo.png"))

    banner = base.backdrop(1280, 400)
    big = base.to_image(g, 10)
    banner.alpha_composite(big, (90, (400 - big.height) // 2))
    d = ImageDraw.Draw(banner)
    x0, gap = 470, 24
    shadow = base.C["K"] + (60,)
    total = sum(7 * px for _, px, _ in WORDMARK + [SUB]) + 9 + gap * 3
    y = (400 - total) // 2
    for text, px, colour in WORDMARK:
        base.word(d, text, x0, y, px, colour + (255,), shadow)
        y += 7 * px + gap
    d.rectangle([x0, y, x0 + max(base.word_width(t, px) for t, px, _ in WORDMARK), y + 9], fill=UNDERLINE + (255,))
    y += 9 + gap
    text, px, colour = SUB
    base.word(d, text, x0, y, px, colour + (255,), shadow)
    banner.save(os.path.join(out, "banner.png"))
    print("wrote docs/plateup/logo-32.png, logo.png, banner.png")


if __name__ == "__main__":
    main()
