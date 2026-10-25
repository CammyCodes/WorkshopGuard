"""Draws every image in the PlateUp! Mod Check theme: art/ (logo, icon, header) and mockups/.

Everything here is drawn from scratch with Pillow: the wooden table, the plates, the tick, the lettering (set in the
bundled OFL fonts). No game asset is used or traced. Run it again any time; it rewrites art/ and mockups/.

    python branding/plateup/tools/make_art.py
"""

from __future__ import annotations

import json
import math
import random
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont

ROOT = Path(__file__).resolve().parents[1]
ART, MOCK, FONTS = ROOT / "art", ROOT / "mockups", ROOT / "fonts"
THEME = json.loads((ROOT / "theme.json").read_text(encoding="utf-8"))
COL = THEME["colors"]

HEAVY = "Baloo2-ExtraBold.ttf"   # wordmark-style lettering, big menu text
BOLD = "Baloo2-Bold.ttf"         # headings
BODY = "VarelaRound-Regular.ttf"  # small text

# Sampled from the game's menus (see DESIGN.md): the table, its darker edges, the soft text shadow, the plate rims
WOOD = (156, 104, 81)
WOOD_EDGE = (131, 87, 68)
SHADOW = (58, 42, 45)
INK = (66, 44, 40)               # our dark outline colour
CREAM = (255, 250, 246)
BLUE = (79, 116, 208)            # tick / wordmark blue
BLUE_LIGHT = (122, 160, 232)
BLUE_DARK = (58, 84, 160)
HIGHLIGHT = (98, 92, 107, 178)   # the menu's translucent grey-purple selection, ~70% over the wood


def rgb(h: str) -> tuple[int, int, int]:
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def font(name: str, px: float) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONTS / name), max(1, int(round(px))))


def shade(c, k: float):
    return tuple(max(0, min(255, int(round(v * k)))) for v in c[:3])


# --- the table --------------------------------------------------------------------------------------------------------
def wood(w: int, h: int, s: float = 1.0, seed: int = 3, base=WOOD, edge=WOOD_EDGE, vignette=True) -> Image.Image:
    """A warm plank table seen from above: narrow vertical boards in short staggered lengths, faint seams."""
    rnd = random.Random(seed)
    im = Image.new("RGB", (w, h), base)
    d = ImageDraw.Draw(im)
    pw = max(4, int(17 * s))
    for x in range(0, w + pw, pw):
        y = -rnd.randint(0, int(160 * s))
        while y < h:
            seg = rnd.randint(int(40 * s), int(170 * s))
            k = 1 + rnd.uniform(-0.035, 0.035)
            d.rectangle([x, y, x + pw - 1, y + seg - 1], fill=shade(base, k))
            seam = shade(base, 0.93)
            d.line([(x, y), (x, y + seg)], fill=seam, width=max(1, int(1.2 * s)))
            d.line([(x, y), (x + pw, y)], fill=shade(base, 0.95), width=max(1, int(1.2 * s)))
            y += seg
    im = im.filter(ImageFilter.GaussianBlur(0.5 * s))
    if vignette:
        # lighter in the middle, darker toward the edges, like the game's table
        m = Image.radial_gradient("L").resize((w, h), Image.BILINEAR)   # 0 centre .. 255 corners
        dark = Image.new("RGB", (w, h), edge)
        im = Image.composite(dark, im, m.point(lambda v: int(min(255, max(0, (v - 70) * 1.25)))))
    return im


# --- plates -----------------------------------------------------------------------------------------------------------
FOODS = ["soup", "tomato", "egg", "peas", "steak", "pie", "salad", "bun", "empty", "pot", "pot2", "fish", "loaf"]


def _blob(d, cx, cy, r, fill, outline, w, rnd, n=9, wob=0.18):
    pts = []
    for i in range(n * 3):
        a = i / (n * 3) * math.tau
        rr = r * (1 + wob * math.sin(a * 3 + rnd.uniform(0, 6)) * 0.5 + rnd.uniform(-wob, wob) * 0.25)
        pts.append((cx + rr * math.cos(a), cy + rr * math.sin(a)))
    d.polygon(pts, fill=fill, outline=outline, width=w)


def plate(layer: Image.Image, shadow: Image.Image, cx: float, cy: float, r: float, kind: str, rnd: random.Random):
    """One top-down dish. Our own simple shapes: a rimmed plate or a two-handled pot, with a cartoon food on it."""
    d = ImageDraw.Draw(layer)
    sd = ImageDraw.Draw(shadow)
    ow = max(1, int(r * 0.055))
    sd.ellipse([cx - r + r * 0.08, cy - r + r * 0.16, cx + r + r * 0.08, cy + r + r * 0.16], fill=150)
    if kind.startswith("pot"):
        metal, inner = (150, 160, 170), (190, 198, 205)
        for sgn in (-1, 1):  # handles
            hx = cx + sgn * r * 1.02
            d.rounded_rectangle([hx - r * 0.2, cy - r * 0.16, hx + r * 0.2, cy + r * 0.16], radius=r * 0.12,
                                fill=metal, outline=INK, width=ow)
        d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=metal, outline=INK, width=ow)
        d.ellipse([cx - r * 0.84, cy - r * 0.84, cx + r * 0.84, cy + r * 0.84], fill=inner)
        liquid = (232, 150, 60) if kind == "pot" else (150, 205, 225)
        d.ellipse([cx - r * 0.74, cy - r * 0.74, cx + r * 0.74, cy + r * 0.74], fill=liquid)
        for _ in range(3):
            a, rr = rnd.uniform(0, math.tau), rnd.uniform(0, r * 0.4)
            px, py = cx + rr * math.cos(a), cy + rr * math.sin(a)
            fr = r * rnd.uniform(0.12, 0.2)
            c = (245, 205, 90) if kind == "pot2" else (200, 95, 50)
            d.ellipse([px - fr, py - fr, px + fr, py + fr], fill=c, outline=shade(c, 0.7), width=max(1, ow // 2))
        return
    rim, well = (206, 200, 203), (230, 226, 225)
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=rim, outline=shade(INK, 1.4), width=ow)
    d.ellipse([cx - r * 0.74, cy - r * 0.74, cx + r * 0.74, cy + r * 0.74], fill=well)
    fw = max(1, int(r * 0.045))
    if kind == "soup":
        d.ellipse([cx - r * 0.6, cy - r * 0.6, cx + r * 0.6, cy + r * 0.6], fill=(196, 70, 52), outline=INK, width=fw)
        d.ellipse([cx - r * 0.2, cy - r * 0.32, cx + r * 0.12, cy - r * 0.02], fill=(245, 236, 220))
    elif kind == "tomato":
        for ox, oy in ((-0.22, 0.05), (0.2, -0.1), (0.05, 0.25)):
            x, y, rr = cx + ox * r, cy + oy * r, r * 0.28
            d.ellipse([x - rr, y - rr, x + rr, y + rr], fill=(222, 66, 52), outline=INK, width=fw)
            d.ellipse([x - rr * 0.3, y - rr * 0.3, x + rr * 0.3, y + rr * 0.3], fill=(90, 160, 70))
    elif kind == "egg":
        _blob(d, cx, cy, r * 0.5, (252, 250, 244), shade(INK, 1.5), fw, rnd)
        d.ellipse([cx - r * 0.2, cy - r * 0.2, cx + r * 0.2, cy + r * 0.2], fill=(250, 180, 40), outline=INK, width=fw)
    elif kind == "peas":
        for _ in range(9):
            a, rr = rnd.uniform(0, math.tau), rnd.uniform(0, r * 0.38)
            x, y, pr = cx + rr * math.cos(a), cy + rr * math.sin(a), r * 0.13
            d.ellipse([x - pr, y - pr, x + pr, y + pr], fill=(110, 180, 70), outline=shade((110, 180, 70), 0.6),
                      width=max(1, fw // 2))
    elif kind == "steak":
        _blob(d, cx, cy + r * 0.04, r * 0.48, (150, 70, 52), INK, fw, rnd, wob=0.3)
        for i in (-1, 0, 1):
            d.line([(cx - r * 0.25 + i * r * 0.18, cy - r * 0.25), (cx + r * 0.05 + i * r * 0.18, cy + r * 0.3)],
                   fill=(100, 45, 35), width=max(1, fw))
    elif kind == "pie":
        d.pieslice([cx - r * 0.62, cy - r * 0.62, cx + r * 0.62, cy + r * 0.62], 200, 290, fill=(236, 186, 92),
                   outline=INK, width=fw)
        d.arc([cx - r * 0.62, cy - r * 0.62, cx + r * 0.62, cy + r * 0.62], 200, 290, fill=(196, 128, 60),
              width=max(2, int(r * 0.12)))
    elif kind == "salad":
        for _ in range(6):
            a, rr = rnd.uniform(0, math.tau), rnd.uniform(0, r * 0.3)
            x, y, lr = cx + rr * math.cos(a), cy + rr * math.sin(a), r * rnd.uniform(0.22, 0.3)
            g = rnd.choice([(120, 190, 80), (90, 160, 70), (150, 205, 95)])
            d.ellipse([x - lr, y - lr, x + lr, y + lr], fill=g, outline=shade(g, 0.65), width=max(1, fw // 2))
    elif kind == "bun":
        d.ellipse([cx - r * 0.55, cy - r * 0.55, cx + r * 0.55, cy + r * 0.55], fill=(226, 160, 86), outline=INK,
                  width=fw)
        for _ in range(6):
            a, rr = rnd.uniform(0, math.tau), rnd.uniform(0, r * 0.35)
            x, y = cx + rr * math.cos(a), cy + rr * math.sin(a)
            d.ellipse([x - r * 0.05, y - r * 0.03, x + r * 0.05, y + r * 0.03], fill=(252, 240, 210))
    elif kind == "fish":
        d.ellipse([cx - r * 0.5, cy - r * 0.22, cx + r * 0.3, cy + r * 0.22], fill=(110, 140, 190), outline=INK,
                  width=fw)
        d.polygon([(cx + r * 0.25, cy), (cx + r * 0.6, cy - r * 0.25), (cx + r * 0.6, cy + r * 0.25)],
                  fill=(110, 140, 190), outline=INK, width=fw)
        d.ellipse([cx - r * 0.38, cy - r * 0.07, cx - r * 0.26, cy + r * 0.05], fill=CREAM)
    elif kind == "loaf":
        d.rounded_rectangle([cx - r * 0.5, cy - r * 0.3, cx + r * 0.5, cy + r * 0.3], radius=r * 0.28,
                            fill=(214, 150, 80), outline=INK, width=fw)
        for i in (-1, 0, 1):
            x = cx + i * r * 0.24
            d.line([(x - r * 0.07, cy + r * 0.14), (x + r * 0.07, cy - r * 0.14)], fill=(245, 214, 160),
                   width=max(1, int(fw * 1.4)))


def table(w: int, h: int, s: float, clear: tuple[float, float] | None, seed: int = 5,
          cell: float = 70, rmin: float = 21, rmax: float = 29, fill: float = 0.82) -> Image.Image:
    """Wood with a grid of dishes, leaving the band clear[0]..clear[1] (fractions of the width) empty."""
    base = wood(w, h, s, seed)
    rnd = random.Random(seed)
    layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    sh = Image.new("L", (w, h), 0)
    step = cell * s
    rows, cols = int(h / step) + 2, int(w / step) + 2
    for j in range(rows):
        for i in range(cols):
            cx, cy = (i + 0.35) * step + rnd.uniform(-3, 3) * s, (j + 0.25) * step + rnd.uniform(-3, 3) * s
            if clear and clear[0] * w - step * 0.6 < cx < clear[1] * w + step * 0.6:
                continue
            if rnd.random() > fill:
                continue
            plate(layer, sh, cx, cy, rnd.uniform(rmin, rmax) * s, rnd.choice(FOODS), rnd)
    sh = sh.filter(ImageFilter.GaussianBlur(5 * s))
    base.paste(Image.new("RGB", (w, h), SHADOW), (0, 0), sh.point(lambda v: v * 0.45))
    base.paste(layer, (0, 0), layer)
    return base


# --- text -------------------------------------------------------------------------------------------------------------
def soft_text(img: Image.Image, xy, text: str, f: ImageFont.FreeTypeFont, fill=CREAM, anchor="mm", s: float = 1.0,
              blur: float = 3.5, off=(1.5, 4), strength: float = 0.85):
    """White text with the game's soft dark drop shadow."""
    m = Image.new("L", img.size, 0)
    ImageDraw.Draw(m).text((xy[0] + off[0] * s, xy[1] + off[1] * s), text, font=f, fill=255, anchor=anchor)
    m = m.filter(ImageFilter.GaussianBlur(blur * s)).point(lambda v: int(v * strength))
    img.paste(Image.new("RGB", img.size, SHADOW), (0, 0), m)
    ImageDraw.Draw(img).text(xy, text, font=f, fill=fill, anchor=anchor)


def lettering(img: Image.Image, xy, text: str, px: float, s: float = 1.0, anchor="lm", tilt: float = -3.0):
    """Chunky wordmark-style lettering (our own): blue with a light top, a thick cream outline, a soft shadow."""
    f = font(HEAVY, px)
    stroke = max(2, int(px * 0.11))
    l, t, r, b = ImageDraw.Draw(img).textbbox((0, 0), text, font=f, anchor="lt", stroke_width=stroke)
    pad = int(px * 0.4)
    W, H = r - l + pad * 2, b - t + pad * 2
    tile = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    o = (pad - l, pad - t)
    # outline + fill masks
    out_m = Image.new("L", (W, H), 0)
    ImageDraw.Draw(out_m).text(o, text, font=f, fill=255, anchor="lt", stroke_width=stroke, stroke_fill=255)
    fill_m = Image.new("L", (W, H), 0)
    ImageDraw.Draw(fill_m).text(o, text, font=f, fill=255, anchor="lt")
    grad = Image.linear_gradient("L").resize((W, H))
    blue = Image.composite(Image.new("RGB", (W, H), BLUE_DARK), Image.new("RGB", (W, H), BLUE_LIGHT),
                           grad.point(lambda v: int(min(255, v * 1.35))))
    tile.paste(Image.new("RGB", (W, H), CREAM), (0, 0), out_m)
    tile.paste(blue, (0, 0), fill_m)
    # a soft gloss along the top of each letter
    gloss = ImageChops.multiply(fill_m, ImageChops.offset(fill_m, 0, int(px * 0.18)))
    gloss = ImageChops.multiply(gloss, Image.linear_gradient("L").rotate(180).resize((W, H)).point(
        lambda v: max(0, v - 150) * 0.55))
    tile.paste(Image.new("RGB", (W, H), (190, 212, 250)), (0, 0), gloss)
    tile = tile.rotate(tilt, resample=Image.BICUBIC, expand=True)
    sh = tile.getchannel("A").filter(ImageFilter.GaussianBlur(px * 0.06)).point(lambda v: int(v * 0.6))
    x, y = xy
    tw, th = tile.size
    if anchor[0] == "m":
        x -= tw / 2
    elif anchor[0] == "r":
        x -= tw
    y -= th / 2
    x, y = int(x), int(y)
    img.paste(Image.new("RGB", tile.size, SHADOW), (x + int(px * 0.03), y + int(px * 0.08)), sh)
    img.paste(tile, (x, y), tile)
    return tw, th


# --- the mark: a plate with a tick ------------------------------------------------------------------------------------
def tick_points(cx, cy, k):
    return [(cx - 0.42 * k, cy + 0.02 * k), (cx - 0.12 * k, cy + 0.3 * k), (cx + 0.46 * k, cy - 0.34 * k)]


def mark(size: int, tile: bool = True, detail: bool = True) -> Image.Image:
    """The Mod Check mark, drawn at 4x and scaled down: a wood tile, a white plate, a big friendly blue tick."""
    S = size * 4
    im = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    u = S / 512
    if tile:
        box = [16 * u, 16 * u, 496 * u, 496 * u]
        m = Image.new("L", (S, S), 0)
        ImageDraw.Draw(m).rounded_rectangle(box, radius=118 * u, fill=255)
        im.paste(Image.new("RGB", (S, S), INK), (0, 0), m)
        inner = Image.new("L", (S, S), 0)
        ImageDraw.Draw(inner).rounded_rectangle([b + (12 * u if i < 2 else -12 * u) for i, b in enumerate(box)],
                                                radius=106 * u, fill=255)
        im.paste(Image.new("RGB", (S, S), CREAM), (0, 0), inner)
        core = Image.new("L", (S, S), 0)
        ImageDraw.Draw(core).rounded_rectangle([b + (30 * u if i < 2 else -30 * u) for i, b in enumerate(box)],
                                               radius=90 * u, fill=255)
        w = wood(S, S, s=S / 512 * 2.2, seed=11, vignette=False) if detail else Image.new("RGB", (S, S), WOOD)
        g = Image.radial_gradient("L").resize((S, S)).point(lambda v: int(max(0, v - 90) * 0.7))
        w = Image.composite(Image.new("RGB", (S, S), WOOD_EDGE), w, g)
        im.paste(w, (0, 0), core)
    cx, cy, r = 256 * u, 262 * u, 178 * u
    # plate shadow
    sh = Image.new("L", (S, S), 0)
    ImageDraw.Draw(sh).ellipse([cx - r + 10 * u, cy - r + 22 * u, cx + r + 10 * u, cy + r + 22 * u], fill=170)
    sh = sh.filter(ImageFilter.GaussianBlur(14 * u))
    if tile:
        sh = ImageChops.multiply(sh, core)
    im.paste(Image.new("RGB", (S, S), SHADOW), (0, 0), sh)
    d = ImageDraw.Draw(im)
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(222, 218, 222), outline=INK, width=int(11 * u))
    rr = r * 0.74
    d.ellipse([cx - rr, cy - rr, cx + rr, cy + rr], fill=(246, 243, 242))
    if detail:
        d.ellipse([cx - rr, cy - rr, cx + rr, cy + rr], outline=(205, 198, 202), width=int(5 * u))
    # tick: dark outline, cream outline, blue body, light top
    pts = tick_points(cx, cy + 8 * u, 282 * u)
    for width, colour in ((112, INK), (90, CREAM), (56, BLUE)):
        d.line(pts, fill=colour, width=int(width * u), joint="curve")
        for p in (pts[0], pts[-1]):
            rad = width * u / 2
            d.ellipse([p[0] - rad, p[1] - rad, p[0] + rad, p[1] + rad], fill=colour)
    if detail:
        hl = [(x - 6 * u, y - 9 * u) for x, y in pts]
        d.line(hl, fill=BLUE_LIGHT, width=int(18 * u), joint="curve")
        for p in (hl[0], hl[-1]):
            rad = 9 * u
            d.ellipse([p[0] - rad, p[1] - rad, p[0] + rad, p[1] + rad], fill=BLUE_LIGHT)
    return im.resize((size, size), Image.LANCZOS)


# --- deliverables -----------------------------------------------------------------------------------------------------
def make_logo():
    mark(512).save(ART / "logo.png", optimize=True)   # the windows show it at 1/8: 64px


def make_icon():
    big = mark(256, detail=False)
    ic = big.resize((32, 32), Image.LANCZOS)
    ic = Image.merge("RGBA", (*ic.convert("RGB").filter(ImageFilter.UnsharpMask(1, 60, 1)).split(), ic.getchannel("A")))
    ic.save(ART / "icon-32.png", optimize=True)
    big.resize((256, 256)).save(ART / "icon-256.png", optimize=True)


def make_header():
    s = 2
    W, H = 620 * s, 110 * s
    bg = rgb(COL["bg"])
    im = table(W, H, s * 0.8, clear=(0.0, 0.62), seed=21, cell=62, rmin=20, rmax=25, fill=0.9)
    # fade the bottom into the dialog background so the header melts into the window
    fade = Image.linear_gradient("L").resize((W, H)).point(lambda v: int(max(0, (v - 150) * 2.4)))
    im = Image.composite(Image.new("RGB", (W, H), bg), im, fade.point(lambda v: min(255, v)))
    lm = mark(int(84 * s))
    im.paste(lm, (int(18 * s), int(12 * s)), lm)
    soft_text(im, (int(112 * s), int(30 * s)), THEME["product"].replace(THEME["short"], "").strip() or "PlateUp!",
              font(BOLD, 21 * s), anchor="lm", s=s * 0.6)
    lettering(im, (int(106 * s), int(64 * s)), THEME["short"], 44 * s, s=s, anchor="lm", tilt=-2)
    im.resize((620, 110), Image.LANCZOS).save(ART / "header.png", optimize=True)


def pill(img, box, fill, radius):
    lay = Image.new("RGBA", img.size, (0, 0, 0, 0))
    ImageDraw.Draw(lay).rounded_rectangle(box, radius=radius, fill=fill)
    img.paste(lay, (0, 0), lay)


def badge(img, xy, text, colour, s, px=17):
    f = font(BOLD, px * s)
    d = ImageDraw.Draw(img)
    l, t, r, b = d.textbbox((0, 0), text, font=f, anchor="ls")
    w, h = r - l + 22 * s, 30 * s
    x, y = xy
    d.rounded_rectangle([x, y, x + w, y + h], radius=8 * s, fill=colour)
    d.text((x + 11 * s, y + h / 2 + 1 * s), text, font=f, fill=rgb(COL["badge_text"]), anchor="lm")
    return w


def caption(img, s):
    soft_text(img, (800 * s, 884 * s), "Concept mockup: PlateUp! Mod Check (unofficial, our own art)",
              font(BODY, 14 * s), fill=(240, 222, 212), s=s * 0.5, strength=0.7)


def mockup_menu():
    s = 2
    W, H = 1600 * s, 900 * s
    im = table(W, H, s, clear=(0.3, 0.7), seed=8)
    cx = W // 2
    f = font(HEAVY, 34 * s)
    items = [("Play", 150), ("Online play", 197), ("Options", 244), ("Mods", 315), ("Mod Preferences", 362),
             ("Open Wiki", 498), ("Join Discord", 545), ("Quit", 636)]
    # the selected item: the game's translucent grey-purple highlight, here on Mods
    pill(im, [cx - 190 * s, 293 * s, cx + 190 * s, 337 * s], HIGHLIGHT, 12 * s)
    for text, y in items:
        soft_text(im, (cx, y * s), text, f, s=s)
    # a count bubble beside "Mods", tomato red like the malicious badge, with a gentle note underneath
    d = ImageDraw.Draw(im)
    bx, by, br = cx + 72 * s, 308 * s, 15 * s
    d.ellipse([bx - br - 3 * s, by - br - 3 * s, bx + br + 3 * s, by + br + 3 * s], fill=CREAM)
    d.ellipse([bx - br, by - br, bx + br, by + br], fill=rgb(COL["malicious"]))
    d.text((bx, by + 1 * s), "1", font=font(HEAVY, 22 * s), fill=rgb(COL["badge_text"]), anchor="mm")
    # the gentle note under Mods: our mark, one line saying what happened, one saying where to look
    l1, l2 = "Mod Check kept 1 mod out of the kitchen", "Open Mods to see which one and why"
    f1, f2 = font(BOLD, 21 * s), font(BODY, 16 * s)
    tw = max(d.textlength(l1, font=f1), d.textlength(l2, font=f2))
    icon_px, gap, padx = int(44 * s), 14 * s, 18 * s
    total = icon_px + gap + tw
    x0, y0 = cx - total / 2, 392 * s
    pill(im, [x0 - padx, y0, x0 + total + padx, y0 + 66 * s], (60, 40, 40, 70), 14 * s)
    ic = mark(icon_px)
    im.paste(ic, (int(x0), int(y0 + 11 * s)), ic)
    soft_text(im, (x0 + icon_px + gap, y0 + 22 * s), l1, f1, anchor="lm", s=s * 0.6)
    soft_text(im, (x0 + icon_px + gap, y0 + 47 * s), l2, f2, fill=(255, 232, 222), anchor="lm", s=s * 0.5)
    soft_text(im, (cx, 836 * s), "Chef", f, s=s)
    caption(im, s)
    im.resize((1600, 900), Image.LANCZOS).save(MOCK / "main-menu-notice.png", optimize=True)


def mockup_panel():
    s = 2
    W, H = 1600 * s, 900 * s
    im = table(W, H, s, clear=(0.24, 0.76), seed=13)
    cx = W // 2
    soft_text(im, (cx, 92 * s), "Blocked mods", font(HEAVY, 46 * s), s=s)
    soft_text(im, (cx, 138 * s), "Mod Check looked at these before PlateUp! started and kept them out of the kitchen.",
              font(BODY, 18 * s), fill=(255, 238, 228), s=s * 0.6)
    # the panel: the menu's translucent highlight, bigger, with a plate-rim edge
    px0, py0, px1, py1 = cx - 380 * s, 176 * s, cx + 380 * s, 650 * s
    pill(im, [px0, py0, px1, py1], (70, 58, 66, 150), 22 * s)
    d = ImageDraw.Draw(im)
    d.rounded_rectangle([px0, py0, px1, py1], radius=22 * s, outline=(214, 196, 196), width=2 * s)
    # stripe + badge + title
    d.rounded_rectangle([px0 + 22 * s, py0 + 26 * s, px0 + 30 * s, py1 - 26 * s], radius=4 * s,
                        fill=rgb(COL["malicious"]))
    x = px0 + 54 * s
    y = py0 + 32 * s
    bw = badge(im, (x, y), "MALICIOUS", rgb(COL["malicious"]), s)
    soft_text(im, (x + bw + 16 * s, y + 15 * s), "Golden Spatula Pack (example)", font(BOLD, 28 * s), anchor="lm",
              s=s * 0.6)
    soft_text(im, (x, y + 62 * s), "Steam Workshop item 9000000001", font(BODY, 17 * s), fill=(244, 222, 212),
              anchor="lm", s=s * 0.5)
    reasons = ["Tries to read your saved browser passwords and logins",
               "Can send what it finds to a server on the internet",
               "Hides a program that would run outside PlateUp!"]
    fy = y + 112 * s
    for r in reasons:
        d = ImageDraw.Draw(im)
        d.ellipse([x + 2 * s, fy - 5 * s, x + 12 * s, fy + 5 * s], fill=CREAM)
        soft_text(im, (x + 28 * s, fy), r, font(BODY, 21 * s), anchor="lm", s=s * 0.5)
        fy += 42 * s
    soft_text(im, (x, fy + 22 * s), "It's been moved to quarantine, so it never loaded.",
              font(BODY, 18 * s), fill=(244, 222, 212), anchor="lm", s=s * 0.5)
    soft_text(im, (x, fy + 52 * s), "Please unsubscribe from it on Steam and report it.",
              font(BODY, 18 * s), fill=(244, 222, 212), anchor="lm", s=s * 0.5)
    # buttons in the menu style: Back selected (highlight), Workshop page plain
    by = 590 * s
    f = font(HEAVY, 30 * s)
    pill(im, [cx - 250 * s, by - 24 * s, cx - 30 * s, by + 24 * s], HIGHLIGHT, 12 * s)
    soft_text(im, (cx - 140 * s, by), "Back", f, s=s)
    soft_text(im, (cx + 140 * s, by), "Workshop page", f, s=s)
    # below the panel, the gentle footer line
    soft_text(im, (cx, 700 * s), "Think this is a mistake? Let the mod's author know.",
              font(BODY, 17 * s), fill=(244, 222, 212), s=s * 0.5)
    soft_text(im, (cx, 836 * s), "Chef", font(HEAVY, 34 * s), s=s)
    caption(im, s)
    im.resize((1600, 900), Image.LANCZOS).save(MOCK / "blocked-mods-panel.png", optimize=True)


def main():
    ART.mkdir(exist_ok=True)
    MOCK.mkdir(exist_ok=True)
    make_logo()
    make_icon()
    make_header()
    mockup_menu()
    mockup_panel()
    print("wrote", *sorted(p.relative_to(ROOT).as_posix() for p in [*ART.glob("*.png"), *MOCK.glob("*.png")]))


if __name__ == "__main__":
    main()
