"""WorkshopGuard's logo as 32x32 pixel art: the GitHub logo, the README banner and small section icons.

A shield with a checkmark, and a little red bug squashed under its edge: the Workshop, kept safe. Drawn on a 32x32
grid from shapes, supersampled per pixel and snapped to a small palette so every pixel is crisp (the same method
as Pho, Realistic Coffee Prices, LemonCosmetics and Nylah).

    python tools/logo/make_logo.py

Outputs:
  docs/logo.png      512 x 512 (GitHub / social)
  docs/banner.png    1280 x 400 (README header)
  docs/logo-32.png   the raw 32 x 32
"""
import math
import os

from PIL import Image, ImageDraw

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
N = 32

C = {
    "K": (22, 32, 52),      # outline
    "B": (74, 144, 226),    # shield
    "b": (46, 104, 182),    # shield shade
    "L": (150, 196, 246),   # shield rim highlight
    "W": (255, 255, 255),   # checkmark
    "R": (226, 72, 77),     # bug
    "r": (160, 40, 50),     # bug shade
    "S": (255, 255, 255),   # sparkle
}
SOFT = ("S",)
BG = ((232, 240, 250), (196, 214, 238))
UNDERLINE = (74, 144, 226)
WORDMARK = [("WORKSHOP", 10, (22, 32, 52)), ("GUARD", 10, (46, 104, 182))]


def shield_half(y):
    """Half-width of the shield at row y (None outside it)."""
    if y < 3.5 or y > 29.5:
        return None
    if y < 17:
        return 11.0 - max(0.0, 5.0 - y) * 0.6   # flat top with softened corners
    t = (y - 17) / 12.5
    return 11.0 * (1 - t ** 1.7)


def near_segment(x, y, ax, ay, bx, by, r):
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(x - (ax + t * dx), y - (ay + t * dy)) <= r


def sample(x, y):
    # Sparkles, top right.
    if sparkle(x, y, 29.5, 3.5, 2.2) or sparkle(x, y, 26.5, 0.5, 1.0):
        return "S"
    # The bug, squashed under the shield's bottom-right edge: antennae, eyes, body, legs.
    if near_segment(x, y, 23.6, 23.8, 22.4, 21.6, 0.45) or near_segment(x, y, 26.4, 23.8, 27.6, 21.6, 0.45):
        return "r"
    if ellipse(x, y, 25.0, 26.0, 3.2, 2.4):
        if ellipse(x, y, 23.9, 25.2, 0.6, 0.6) or ellipse(x, y, 26.1, 25.2, 0.6, 0.6):
            return "W"
        return "r" if y > 26.6 else "R"
    for lx in (22.6, 25.0, 27.4):
        if abs(x - lx) < 0.5 and 28.0 <= y < 30.0:
            return "r"
    # Shield.
    half = shield_half(y)
    if half is not None and abs(x - 15.5) <= half:
        if near_segment(x, y, 9.5, 16.5, 13.8, 21.0, 1.55) or near_segment(x, y, 13.8, 21.0, 22.0, 10.5, 1.55):
            return "W"
        if abs(x - 15.5) > half - 1.2 or y < 5.0:
            return "L" if x < 15.5 else "b"
        return "B" if x < 15.5 else "b"
    return "."


def decorate(d, w, h):
    """Soft dotted rings, like Pho's banner."""
    u = max(3, h // 100)
    for cx, cy in ((0.07, 0.17), (0.62, 0.1), (0.95, 0.18), (0.33, 0.88), (0.94, 0.8)):
        x0, y0 = int(cx * w), int(cy * h)
        for a in range(0, 360, 45):
            px = x0 + int(math.cos(math.radians(a)) * u * 3)
            py = y0 + int(math.sin(math.radians(a)) * u * 3)
            d.rectangle([px, py, px + u - 1, py + u - 1], fill=(255, 255, 255, 170))


# ---------------------------------------------------------------- drawing (same method as Pho / Realistic Coffee)

def ellipse(x, y, cx, cy, rx, ry):
    return ((x - cx) / rx) ** 2 + ((y - cy) / ry) ** 2 <= 1.0


def sparkle(x, y, cx, cy, r):
    """A four-point star, one pixel wide."""
    return (abs(x - cx) < 0.5 and abs(y - cy) < r) or (abs(y - cy) < 0.5 and abs(x - cx) < r)


def pixel(px, py):
    votes = {}
    for sy in range(4):
        for sx in range(4):
            k = sample(px + (sx + 0.5) / 4, py + (sy + 0.5) / 4)
            votes[k] = votes.get(k, 0) + 1
    k = max(votes, key=votes.get)
    return None if k == "." else k


def grid():
    return [[pixel(x, y) for x in range(N)] for y in range(N)]


def outline(g):
    out = [row[:] for row in g]
    for y in range(N):
        for x in range(N):
            if g[y][x] is None:
                for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
                    nx, ny = x + dx, y + dy
                    if 0 <= nx < N and 0 <= ny < N and g[ny][nx] not in (None, "K") + SOFT:
                        out[y][x] = "K"
                        break
    return out


def to_image(g, scale):
    img = Image.new("RGBA", (N * scale, N * scale), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    for y in range(N):
        for x in range(N):
            k = g[y][x]
            if k:
                d.rectangle([x * scale, y * scale, (x + 1) * scale - 1, (y + 1) * scale - 1], fill=C[k] + (255,))
    return img


FONT = {
    "A": ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
    "D": ["11110", "10001", "10001", "10001", "10001", "10001", "11110"],
    "G": ["01111", "10000", "10000", "10011", "10001", "10001", "01111"],
    "H": ["10001", "10001", "10001", "11111", "10001", "10001", "10001"],
    "K": ["10001", "10010", "10100", "11000", "10100", "10010", "10001"],
    "O": ["01110", "10001", "10001", "10001", "10001", "10001", "01110"],
    "P": ["11110", "10001", "10001", "11110", "10000", "10000", "10000"],
    "R": ["11110", "10001", "10001", "11110", "10100", "10010", "10001"],
    "S": ["01111", "10000", "10000", "01110", "00001", "00001", "11110"],
    "U": ["10001", "10001", "10001", "10001", "10001", "10001", "01110"],
    "W": ["10001", "10001", "10001", "10101", "10101", "11011", "10001"],
    " ": ["000"],
}


def word_width(text, px):
    return sum((len(FONT[ch][0]) + 1) * px for ch in text) - px


def word(d, text, x, y, px, colour, shadow):
    for ch in text:
        rows = FONT[ch]
        for ry, row in enumerate(rows):
            for rx, bit in enumerate(row):
                if bit == "1":
                    d.rectangle([x + rx * px + px // 3, y + ry * px + px // 3, x + (rx + 1) * px - 1 + px // 3,
                                 y + (ry + 1) * px - 1 + px // 3], fill=shadow)
                    d.rectangle([x + rx * px, y + ry * px, x + (rx + 1) * px - 1, y + (ry + 1) * px - 1], fill=colour)
        x += (len(rows[0]) + 1) * px
    return x


def backdrop(w, h):
    img = Image.new("RGBA", (w, h))
    d = ImageDraw.Draw(img)
    top, bottom = BG
    for y in range(h):
        t = y / max(1, h - 1)
        d.line([(0, y), (w, y)], fill=tuple(int(top[i] + (bottom[i] - top[i]) * t) for i in range(3)) + (255,))
    decorate(d, w, h)
    return img


def main():
    g = outline(grid())
    docs = os.path.join(ROOT, "docs")
    os.makedirs(docs, exist_ok=True)
    to_image(g, 1).save(os.path.join(docs, "logo-32.png"))

    logo = backdrop(512, 512)
    mask = Image.new("L", (512, 512), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, 511, 511], radius=96, fill=255)
    sprite = to_image(g, 14)
    logo.alpha_composite(sprite, ((512 - sprite.width) // 2, (512 - sprite.height) // 2))
    logo.putalpha(mask)
    logo.save(os.path.join(docs, "logo.png"))

    banner = backdrop(1280, 400)
    big = to_image(g, 10)
    banner.alpha_composite(big, (90, (400 - big.height) // 2))
    d = ImageDraw.Draw(banner)
    x0 = 470
    widths = [word_width(text, px) for text, px, _ in WORDMARK]
    heights = [7 * px for _, px, _ in WORDMARK]
    gap = 28
    y = (400 - (sum(heights) + gap * len(WORDMARK) + 10)) // 2
    for (text, px, colour), h in zip(WORDMARK, heights):
        word(d, text, x0, y, px, colour + (255,), C["K"] + (60,))
        y += h + gap
    d.rectangle([x0, y, x0 + max(widths), y + 9], fill=UNDERLINE + (255,))
    banner.save(os.path.join(docs, "banner.png"))
    print("wrote docs/logo-32.png, docs/logo.png, docs/banner.png")


if __name__ == "__main__":
    main()
