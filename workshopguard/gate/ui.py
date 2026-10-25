"""The gate's windows: a small progress window while mods are scanned, and the dialog when something is flagged.

No window at all when nothing changed. Everything else (scanning, hashing) runs off the UI thread. With
WG_GATE_HEADLESS=1 there's no Tk at all and WG_GATE_ANSWER answers dialogs (play | quit | allow | repair), for tests.

Every colour, font, image and sentence a player sees comes from a theme: a built-in one ("default", "plateup") or a
theme folder with a theme.json (see branding/), so a game team can ship it under their own name and look.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
import webbrowser
from dataclasses import dataclass, field, replace
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DOCS = REPO / "docs"
FALLBACK_FONT = "Segoe UI"

STRINGS = {
    # progress window
    "checking_one": "Checking 1 new or updated mod…",
    "checking_many": "Checking {n} new or updated mods…",
    "checking_game": "Checking {game}'s files…",
    "starts_after": "{game} starts as soon as this is done",
    # decision dialog
    "title_stopped_one": "{short} stopped a dangerous mod",
    "title_stopped_many": "{short} stopped {n} dangerous mods",
    "title_look_one": "Something needs a look before {game} starts",
    "title_look_many": "{n} things need a look before {game} starts",
    "subtitle_one": "{game} hasn't started yet, so nothing in it has run.",
    "subtitle_many": "{game} hasn't started yet, so nothing in these has run.",
    "badge_malicious": "MALICIOUS",
    "badge_suspicious": "SUSPICIOUS",
    "badge_game": "GAME FILES",
    "workshop_item": "Steam Workshop item {id}",
    "local_mod": "Local mod folder",
    "game_files_title": "{game}'s own files",
    "note_malicious_workshop": "It will be moved to quarantine. Unsubscribe from it on Steam and report it.",
    "note_malicious": "It will be moved to quarantine.",
    "note_suspicious": "Left off unless you tick the box. Your answer is remembered until the mod changes.",
    "note_game": "If you didn't install anything into the game folder, repair it with Steam.",
    "trust": "I trust this version: load it anyway",
    "workshop_page": "Workshop page",
    "quit": "Quit",
    "repair": "Repair game files",
    "play": "Play",
    "play_without_one": "Play without it",
    "play_without_many": "Play without them",
    "quarantine_line": "Blocked mods are moved to {path}",
    # alerts
    "closed_title": "{short} closed {game}",
    "closed_body": "It started loading mods from folders that weren't checked first:\n\n{folders}\n\n"
                   "Start the game again and they'll be checked.",
    "update_title": "{short} blocked an update to '{mod}'",
    "update_body": "Steam just downloaded an update to this mod and it looks malicious:\n\n{reasons}\n\n"
                   "It's been moved to quarantine before it could load. The copy in this game session is the earlier "
                   "version, which was checked. Unsubscribe from it on Steam.",
    "move_title": "{short} couldn't move a blocked mod",
    "move_body_nomods": "Its folder is in use, so {game} will start with mods turned off this time.",
    "move_body_quit": "Its folder is in use. Close anything using it and start the game again.",
    "error_title": "{short} couldn't check your mods",
    "error_body": "{error}\n\nYour mods haven't been checked, so the safe choice is to quit and try again. "
                  "Details are in {log}.",
    "error_quit": "Quit",
    "error_play_nomods": "Play without mods",
    "error_play": "Play anyway",
    "ok": "OK",
    # demo
    "demo_title": "That's the demo",
    "demo_body_play": "In real use, {game} would start now with the clean mod. The malicious one would be in "
                      "quarantine. {kept}\n\nNext launch, nothing has changed, so there's no window at all: the game "
                      "starts in about half a second.\n\nNothing was scanned, moved or started.",
    "demo_kept_allowed": "The suspicious one loads too, as you allowed.",
    "demo_kept_off": "Both flagged mods stay off.",
    "demo_body_quit": "In real use, {game} wouldn't start. The malicious mod would still go to quarantine.\n\n"
                      "Nothing was scanned, moved or started.",
    "demo_close": "Close",
}

COLORS = {
    "bg": "#141c26", "card": "#1e2a38", "border": "#2c3e52", "text": "#e8eef5", "dim": "#93a4b8",
    "malicious": "#e2484d", "suspicious": "#f0b03f", "game": "#4a90e2", "badge_text": "#10161e",
    "primary": "#57c27a", "primary_hover": "#6fd690", "primary_text": "#10161e",
    "secondary": "#1e2a38", "secondary_hover": "#2a3a4d", "secondary_text": "#e8eef5",
    "link": "#4a90e2", "progress": "#57c27a", "progress_trough": "#1e2a38",
}


@dataclass
class Theme:
    product: str = "WorkshopGuard"          # window titles and the small brand line
    short: str = "WorkshopGuard"            # in sentences: "{short} stopped a dangerous mod"
    logo: Path | None = DOCS / "logo.png"   # shown at 1/8 size
    icon: Path | None = DOCS / "logo-32.png"
    header: Path | None = None              # optional strip across the top of the decision dialog
    font_files: list[Path] = field(default_factory=list)
    body_font: str = FALLBACK_FONT
    heading_font: str = FALLBACK_FONT
    colors: dict = field(default_factory=lambda: dict(COLORS))
    strings: dict = field(default_factory=lambda: dict(STRINGS))

    def c(self, key: str) -> str:
        return self.colors.get(key) or COLORS[key]


class _Keep(dict):
    def __missing__(self, key):          # an unknown {placeholder} in a theme's text stays as written
        return "{" + key + "}"


BUILTIN = {
    "default": Theme(),
    # WorkshopGuard's PlateUp! edition: warm kitchen colours and the chef's-hat shield (our own art)
    "plateup": Theme(product="WorkshopGuard for PlateUp!", logo=DOCS / "plateup" / "logo.png",
                     icon=DOCS / "plateup" / "logo-32.png",
                     colors={**COLORS, "bg": "#22160e", "card": "#34241a", "border": "#4a3426", "text": "#fbefdc",
                             "dim": "#c9ab8b", "game": "#7fb4f0", "primary": "#f08a2c", "primary_hover": "#f7a44f",
                             "secondary": "#34241a", "secondary_hover": "#4a3426", "secondary_text": "#fbefdc",
                             "link": "#7fb4f0", "progress": "#f08a2c", "progress_trough": "#34241a"}),
}


def load_theme(spec: str | Path | None) -> Theme:
    """A built-in theme by name, or a theme folder (or its theme.json), relative to the repo or absolute."""
    if not spec:
        return replace(BUILTIN["default"])
    if str(spec) in BUILTIN:
        t = BUILTIN[str(spec)]
        return replace(t, colors=dict(t.colors), strings=dict(t.strings))
    p = Path(spec)
    if not p.is_absolute():
        p = REPO / p
    if p.is_dir():
        p = p / "theme.json"
    raw = json.loads(p.read_text(encoding="utf-8"))
    base = p.parent

    def path(key):
        return base / raw[key] if raw.get(key) else None

    fonts = raw.get("fonts") or {}
    return Theme(
        product=raw.get("product", "Mod Check"), short=raw.get("short", raw.get("product", "Mod Check")),
        logo=path("logo"), icon=path("icon"), header=path("header"),
        font_files=[base / f for f in fonts.get("files", [])],
        body_font=fonts.get("body", FALLBACK_FONT), heading_font=fonts.get("heading", fonts.get("body", FALLBACK_FONT)),
        colors={**COLORS, **(raw.get("colors") or {})}, strings={**STRINGS, **(raw.get("strings") or {})},
    )


@dataclass
class Problem:
    key: str
    title: str
    where: str
    verdict: str                     # malicious | suspicious | game
    reasons: list[tuple[str, str]]   # (description, file)
    can_allow: bool = False
    note: str = ""
    link: str = ""


@dataclass
class Answer:
    action: str = "quit"             # play | quit | repair
    allow: set[str] = field(default_factory=set)


def headless() -> bool:
    return os.environ.get("WG_GATE_HEADLESS") == "1"


class UI:
    def __init__(self, game_name: str, splash_after: float = 0.35, theme: str | Path | Theme | None = "default"):
        self.game_name = game_name
        self.splash_after = splash_after
        self.theme = theme if isinstance(theme, Theme) else load_theme(theme)
        self.root = None
        self._logo = self._header = None

    @property
    def brand(self) -> str:
        return self.theme.product

    def s(self, key: str, **kw) -> str:
        """A sentence from the theme, with {game}, {short} and the given placeholders filled in."""
        text = self.theme.strings.get(key) or STRINGS.get(key, key)
        return text.format_map(_Keep(game=self.game_name, short=self.theme.short, **kw))

    # --- plumbing -------------------------------------------------------------------------------------------------
    def _tk(self):
        if self.root is None:
            try:
                from ctypes import windll
                windll.shcore.SetProcessDpiAwareness(1)
                for f in self.theme.font_files:   # private to this process: nothing is installed
                    windll.gdi32.AddFontResourceExW(str(f), 0x10, 0)
            except Exception:  # noqa: BLE001 - not Windows, or an old one
                pass
            import tkinter as tk
            import tkinter.font as tkfont
            self.tk = tk
            self.root = tk.Tk()
            self.root.withdraw()
            self.root.title(self.brand)
            self.root.configure(bg=self.theme.c("bg"))
            families = set(tkfont.families(self.root))
            self.body = self.theme.body_font if self.theme.body_font in families else FALLBACK_FONT
            self.heading = self.theme.heading_font if self.theme.heading_font in families else self.body
            try:
                if self.theme.logo:
                    self._logo = tk.PhotoImage(file=str(self.theme.logo)).subsample(8)
                if self.theme.icon:
                    self.root.iconphoto(True, tk.PhotoImage(file=str(self.theme.icon)))
                if self.theme.header and self.theme.header.is_file():
                    self._header = tk.PhotoImage(file=str(self.theme.header))
            except Exception:  # noqa: BLE001 - a missing image mustn't stop the game
                pass
        return self.root

    def _place(self, win, w: int, h: int):
        win.update_idletasks()
        sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
        win.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 3}")

    def _button(self, parent, text, cmd, primary=False):
        c = self.theme.c
        return self.tk.Button(parent, text=text, command=cmd, font=(self.heading if primary else self.body, 10,
                                                                     "bold" if primary else "normal"),
                              bg=c("primary") if primary else c("secondary"),
                              fg=c("primary_text") if primary else c("secondary_text"),
                              activebackground=c("primary_hover") if primary else c("secondary_hover"),
                              activeforeground=c("primary_text") if primary else c("secondary_text"),
                              relief="flat", bd=0, padx=16, pady=6, cursor="hand2")

    def close(self):
        if self.root is not None:
            try:
                self.root.destroy()
            except Exception:  # noqa: BLE001
                pass
            self.root = None

    # --- progress -------------------------------------------------------------------------------------------------
    def run(self, fn, heading: str):
        """Run fn(progress) on a worker thread. A progress window appears only if it takes a while."""
        q: queue.Queue = queue.Queue()
        box: dict = {}

        def work():
            try:
                box["result"] = fn(lambda text, frac=None: q.put((text, frac)))
            except BaseException as e:  # noqa: BLE001 - handed back to the caller
                box["error"] = e

        t = threading.Thread(target=work, daemon=True, name="gate-scan")
        t.start()
        t.join(self.splash_after)
        if t.is_alive() and not headless():
            self._progress(t, q, heading)
        t.join()
        if "error" in box:
            raise box["error"]
        return box.get("result")

    def _progress(self, t, q, heading):
        c = self.theme.c
        root = self._tk()
        tk = self.tk
        from tkinter import ttk
        bg = c("bg")
        win = tk.Toplevel(root, bg=bg)
        win.overrideredirect(True)
        win.attributes("-topmost", True)
        outer = tk.Frame(win, bg=bg, highlightthickness=1, highlightbackground=c("border"))
        outer.pack(fill="both", expand=True)
        row = tk.Frame(outer, bg=bg)
        row.pack(fill="x", padx=18, pady=(16, 6))
        if self._logo:
            tk.Label(row, image=self._logo, bg=bg).pack(side="left", padx=(0, 14))
        txt = tk.Frame(row, bg=bg)
        txt.pack(side="left", fill="x", expand=True)
        tk.Label(txt, text=self.brand, bg=bg, fg=c("dim"), font=(self.body, 9)).pack(anchor="w")
        tk.Label(txt, text=heading, bg=bg, fg=c("text"), font=(self.heading, 12, "bold"), anchor="w",
                 justify="left").pack(anchor="w", fill="x")
        sub = tk.Label(txt, text=self.s("starts_after"), bg=bg, fg=c("dim"), font=(self.body, 9), anchor="w")
        sub.pack(anchor="w", fill="x")
        style = ttk.Style(win)
        style.theme_use("default")
        style.configure("G.Horizontal.TProgressbar", troughcolor=c("progress_trough"), background=c("progress"),
                        bordercolor=bg, lightcolor=c("progress"), darkcolor=c("progress"), thickness=6)
        bar = ttk.Progressbar(outer, style="G.Horizontal.TProgressbar", mode="indeterminate", length=380)
        bar.pack(fill="x", padx=18, pady=(8, 16))
        bar.start(12)
        win.update_idletasks()   # size to the content: fonts and Windows scaling change the height
        self._place(win, max(460, outer.winfo_reqwidth()), max(128, outer.winfo_reqheight()))
        win.deiconify()
        mode = "indeterminate"
        while t.is_alive():
            try:
                while True:
                    text, frac = q.get_nowait()
                    if text:
                        sub.configure(text=text[:70])
                    if frac is not None:
                        if mode != "determinate":
                            bar.stop()
                            bar.configure(mode="determinate", maximum=1000)
                            mode = "determinate"
                        bar["value"] = int(max(0.0, min(1.0, frac)) * 1000)
            except queue.Empty:
                pass
            try:
                root.update()
            except Exception:  # noqa: BLE001 - window closed under us
                break
            time.sleep(0.03)
        try:
            win.destroy()
            root.update()
        except Exception:  # noqa: BLE001
            pass

    # --- decisions ------------------------------------------------------------------------------------------------
    def ask(self, problems: list[Problem], quarantine_dir: Path) -> Answer:
        if headless():
            a = os.environ.get("WG_GATE_ANSWER", "play")
            if a == "allow":
                return Answer("play", {p.key for p in problems if p.can_allow})
            return Answer(a if a in ("play", "quit", "repair") else "play")
        c = self.theme.c
        root = self._tk()
        tk = self.tk
        bg, card, fg, dim = c("bg"), c("card"), c("text"), c("dim")
        win = tk.Toplevel(root, bg=bg)
        win.title(self.brand)
        win.attributes("-topmost", True)
        win.resizable(False, True)
        ans = Answer("quit")
        allow_vars: dict[str, object] = {}
        bad = sum(p.verdict == "malicious" for p in problems)
        n = len(problems)

        if self._header:
            tk.Label(win, image=self._header, bg=bg, bd=0).pack(fill="x")
        top = tk.Frame(win, bg=bg)
        top.pack(fill="x", padx=20, pady=(18, 8))
        if self._logo and not self._header:
            tk.Label(top, image=self._logo, bg=bg).pack(side="left", padx=(0, 14))
        hd = tk.Frame(top, bg=bg)
        hd.pack(side="left", fill="x", expand=True)
        if bad:
            title = self.s("title_stopped_one") if bad == 1 else self.s("title_stopped_many", n=bad)
        else:
            title = self.s("title_look_one") if n == 1 else self.s("title_look_many", n=n)
        tk.Label(hd, text=title, bg=bg, fg=fg, font=(self.heading, 13, "bold"), anchor="w", justify="left",
                 wraplength=540 if self._header else 470).pack(anchor="w")
        tk.Label(hd, text=self.s("subtitle_one" if n == 1 else "subtitle_many"), bg=bg, fg=dim,
                 font=(self.body, 9), anchor="w").pack(anchor="w", pady=(2, 0))

        # scrollable list of cards
        holder = tk.Frame(win, bg=bg)
        holder.pack(fill="both", expand=True, padx=20)
        canvas = tk.Canvas(holder, bg=bg, highlightthickness=0, width=560)
        inner = tk.Frame(canvas, bg=bg)
        wid = canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(wid, width=e.width))
        canvas.pack(side="left", fill="both", expand=True)

        for p in problems:
            color = c({"malicious": "malicious", "suspicious": "suspicious"}.get(p.verdict, "game"))
            label = self.s({"malicious": "badge_malicious", "suspicious": "badge_suspicious"}.get(p.verdict,
                                                                                                  "badge_game"))
            box = tk.Frame(inner, bg=card, highlightthickness=1, highlightbackground=c("border"))
            box.pack(fill="x", pady=5)
            tk.Frame(box, bg=color, width=5).pack(side="left", fill="y")
            body = tk.Frame(box, bg=card)
            body.pack(side="left", fill="x", expand=True, padx=12, pady=10)
            line = tk.Frame(body, bg=card)
            line.pack(fill="x")
            tk.Label(line, text=label, bg=color, fg=c("badge_text"), font=(self.heading, 8, "bold"),
                     padx=6).pack(side="left")
            tk.Label(line, text=f"  {p.title}", bg=card, fg=fg, font=(self.heading, 10, "bold"),
                     anchor="w").pack(side="left")
            tk.Label(body, text=p.where, bg=card, fg=dim, font=(self.body, 8), anchor="w", justify="left",
                     wraplength=500).pack(anchor="w", pady=(2, 4))
            for desc, f in p.reasons[:4]:
                t = f"•  {desc}" + (f"   ({f})" if f else "")
                tk.Label(body, text=t, bg=card, fg=fg, font=(self.body, 9), anchor="w", justify="left",
                         wraplength=500).pack(anchor="w")
            if len(p.reasons) > 4:
                tk.Label(body, text=f"…and {len(p.reasons) - 4} more", bg=card, fg=dim,
                         font=(self.body, 8)).pack(anchor="w")
            foot = tk.Frame(body, bg=card)
            foot.pack(fill="x", pady=(6, 0))
            if p.note:
                tk.Label(foot, text=p.note, bg=card, fg=dim, font=(self.body, 8), anchor="w", justify="left",
                         wraplength=380).pack(side="left")
            if p.link:
                lk = tk.Label(foot, text=self.s("workshop_page"), bg=card, fg=c("link"),
                              font=(self.body, 8, "underline"), cursor="hand2")
                lk.pack(side="right")
                lk.bind("<Button-1>", lambda _e, u=p.link: webbrowser.open(u))
            if p.can_allow:
                v = tk.BooleanVar(value=False)
                allow_vars[p.key] = v
                tk.Checkbutton(body, text=self.s("trust"), variable=v, bg=card, fg=fg, selectcolor=bg,
                               activebackground=card, activeforeground=fg, font=(self.body, 9),
                               command=lambda: refresh()).pack(anchor="w", pady=(6, 0))

        btns = tk.Frame(win, bg=bg)
        btns.pack(fill="x", padx=20, pady=(10, 18))

        def done(action):
            ans.action = action
            ans.allow = {k for k, v in allow_vars.items() if v.get()}
            win.destroy()

        self._button(btns, self.s("quit"), lambda: done("quit")).pack(side="left")
        if any(p.verdict == "game" for p in problems):
            self._button(btns, self.s("repair"), lambda: done("repair")).pack(side="left", padx=(8, 0))
        play = self._button(btns, "", lambda: done("play"), primary=True)
        play.pack(side="right")

        def refresh():
            blocked = sum(1 for p in problems if not (p.can_allow and allow_vars[p.key].get()))
            play.configure(text=self.s("play") if blocked == 0 else
                           self.s("play_without_one" if blocked == 1 else "play_without_many"))

        refresh()
        tk.Label(win, text=self.s("quarantine_line", path=quarantine_dir), bg=bg, fg=dim, font=(self.body, 8),
                 anchor="w", justify="left", wraplength=580).pack(anchor="w", padx=20, pady=(0, 10))
        win.protocol("WM_DELETE_WINDOW", lambda: done("quit"))
        win.bind("<Escape>", lambda _e: done("quit"))
        win.update_idletasks()
        h = min(inner.winfo_reqheight(), max(420, int(win.winfo_screenheight() * 0.55)))
        canvas.configure(height=h, scrollregion=(0, 0, 560, inner.winfo_reqheight()))
        if inner.winfo_reqheight() > h:
            sb = tk.Scrollbar(holder, command=canvas.yview)
            sb.pack(side="right", fill="y")
            canvas.configure(yscrollcommand=sb.set)
            canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-e.delta / 120), "units"))
        win.update_idletasks()
        self._place(win, 620, win.winfo_reqheight())
        win.deiconify()
        win.lift()
        win.focus_force()
        play.focus_set()
        root.wait_window(win)
        return ans

    def alert(self, title: str, text: str, buttons: tuple[str, ...] | None = None, default: int = -1) -> str:
        """A simple message with buttons, laid out left to right; returns the one pressed. `default` is the
        highlighted button (the last one unless the safe choice is another)."""
        buttons = buttons or (self.s("ok"),)
        default = default % len(buttons)
        if headless():
            return os.environ.get("WG_GATE_ALERT", buttons[default])
        c = self.theme.c
        self._tk()
        tk = self.tk
        bg = c("bg")
        win = tk.Toplevel(self.root, bg=bg)
        win.title(self.brand)
        win.attributes("-topmost", True)
        win.resizable(False, False)
        res = {"b": buttons[0]}
        top = tk.Frame(win, bg=bg)
        top.pack(fill="x", padx=20, pady=18)
        if self._logo:
            tk.Label(top, image=self._logo, bg=bg).pack(side="left", padx=(0, 14), anchor="n")
        box = tk.Frame(top, bg=bg)
        box.pack(side="left", fill="x", expand=True)
        tk.Label(box, text=title, bg=bg, fg=c("text"), font=(self.heading, 12, "bold"), anchor="w", justify="left",
                 wraplength=420).pack(anchor="w")
        tk.Label(box, text=text, bg=bg, fg=c("text"), font=(self.body, 9), anchor="w", justify="left",
                 wraplength=420).pack(anchor="w", pady=(6, 0))
        row = tk.Frame(win, bg=bg)
        row.pack(fill="x", padx=20, pady=(0, 18))

        def pick(b):
            res["b"] = b
            win.destroy()

        for i, b in reversed(list(enumerate(buttons))):
            btn = self._button(row, b, lambda b=b: pick(b), primary=i == default)
            btn.pack(side="right", padx=(8, 0))
            if i == default:
                btn.focus_set()
        win.protocol("WM_DELETE_WINDOW", lambda: pick(buttons[0]))
        win.update_idletasks()
        self._place(win, 540, win.winfo_reqheight())
        win.deiconify()
        win.focus_force()
        self.root.wait_window(win)
        return res["b"]
