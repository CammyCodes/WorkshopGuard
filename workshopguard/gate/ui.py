"""The gate's windows: a small progress window while mods are scanned, and the dialog when something is flagged.

No window at all when nothing changed. Everything else (scanning, hashing) runs off the UI thread. With
WG_GATE_HEADLESS=1 there's no Tk at all and WG_GATE_ANSWER answers dialogs (play | quit | allow | repair), for tests.
"""

from __future__ import annotations

import os
import queue
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path

DOCS = Path(__file__).resolve().parents[2] / "docs"
FONT = "Segoe UI"
# name: (brand line, logo, colours: background, card, text, dim text, malicious, suspicious, primary button, link,
#        primary button hovered)
THEMES = {
    "default": ("WorkshopGuard", DOCS / "logo.png",
                ("#141c26", "#1e2a38", "#e8eef5", "#93a4b8", "#e2484d", "#f0b03f", "#57c27a", "#4a90e2", "#6fd690")),
    # PlateUp!: warm kitchen colours and the chef's-hat logo (our own art, nothing taken from the game)
    "plateup": ("WorkshopGuard for PlateUp!", DOCS / "plateup" / "logo.png",
                ("#22160e", "#34241a", "#fbefdc", "#c9ab8b", "#e2484d", "#f0b03f", "#f08a2c", "#7fb4f0", "#f7a44f")),
}


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
    def __init__(self, game_name: str, splash_after: float = 0.35, theme: str = "default"):
        self.game_name = game_name
        self.splash_after = splash_after
        self.brand, self.logo_path, self.colors = THEMES.get(theme, THEMES["default"])
        self.root = None
        self._logo = None

    # --- plumbing -------------------------------------------------------------------------------------------------
    def _tk(self):
        if self.root is None:
            import tkinter as tk
            self.tk = tk
            self.root = tk.Tk()
            self.root.withdraw()
            self.root.title(self.brand)
            self.root.configure(bg=self.colors[0])
            try:
                self._logo = tk.PhotoImage(file=str(self.logo_path)).subsample(8)
                self.root.iconphoto(True, tk.PhotoImage(file=str(self.logo_path.with_name("logo-32.png"))))
            except Exception:  # noqa: BLE001 - a missing image mustn't stop the game
                self._logo = None
            try:
                from ctypes import windll
                windll.shcore.SetProcessDpiAwareness(1)
            except Exception:  # noqa: BLE001
                pass
        return self.root

    def _place(self, win, w: int, h: int):
        win.update_idletasks()
        sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
        win.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 3}")

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
        BG, CARD, FG, DIM, RED, AMBER, GREEN, BLUE, HOT = self.colors
        root = self._tk()
        tk = self.tk
        from tkinter import ttk
        win = tk.Toplevel(root, bg=BG)
        win.overrideredirect(True)
        win.attributes("-topmost", True)
        outer = tk.Frame(win, bg=BG, highlightthickness=1, highlightbackground="#2c3e52")
        outer.pack(fill="both", expand=True)
        row = tk.Frame(outer, bg=BG)
        row.pack(fill="x", padx=18, pady=(16, 6))
        if self._logo:
            tk.Label(row, image=self._logo, bg=BG).pack(side="left", padx=(0, 14))
        txt = tk.Frame(row, bg=BG)
        txt.pack(side="left", fill="x", expand=True)
        tk.Label(txt, text=self.brand, bg=BG, fg=DIM, font=(FONT, 9)).pack(anchor="w")
        head = tk.Label(txt, text=heading, bg=BG, fg=FG, font=(FONT, 12, "bold"), anchor="w", justify="left")
        head.pack(anchor="w", fill="x")
        sub = tk.Label(txt, text=f"{self.game_name} starts as soon as this is done", bg=BG, fg=DIM,
                       font=(FONT, 9), anchor="w")
        sub.pack(anchor="w", fill="x")
        style = ttk.Style(win)
        style.theme_use("default")
        style.configure("G.Horizontal.TProgressbar", troughcolor=CARD, background=GREEN, bordercolor=BG,
                        lightcolor=GREEN, darkcolor=GREEN, thickness=6)
        bar = ttk.Progressbar(outer, style="G.Horizontal.TProgressbar", mode="indeterminate", length=380)
        bar.pack(fill="x", padx=18, pady=(8, 16))
        bar.start(12)
        self._place(win, 460, 128)
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
        BG, CARD, FG, DIM, RED, AMBER, GREEN, BLUE, HOT = self.colors
        if headless():
            a = os.environ.get("WG_GATE_ANSWER", "play")
            if a == "allow":
                return Answer("play", {p.key for p in problems if p.can_allow})
            return Answer(a if a in ("play", "quit", "repair") else "play")
        root = self._tk()
        tk = self.tk
        win = tk.Toplevel(root, bg=BG)
        win.title(self.brand)
        win.attributes("-topmost", True)
        win.resizable(False, True)
        ans = Answer("quit")
        allow_vars: dict[str, object] = {}
        bad = sum(p.verdict == "malicious" for p in problems)

        top = tk.Frame(win, bg=BG)
        top.pack(fill="x", padx=20, pady=(18, 8))
        if self._logo:
            tk.Label(top, image=self._logo, bg=BG).pack(side="left", padx=(0, 14))
        hd = tk.Frame(top, bg=BG)
        hd.pack(side="left", fill="x", expand=True)
        n = len(problems)
        if bad:
            title = f"WorkshopGuard stopped {'a dangerous mod' if bad == 1 else f'{bad} dangerous mods'}"
        else:
            title = f"{'Something needs' if n == 1 else f'{n} things need'} a look before {self.game_name} starts"
        tk.Label(hd, text=title, bg=BG, fg=FG, font=(FONT, 13, "bold"), anchor="w", justify="left",
                 wraplength=470).pack(anchor="w")
        tk.Label(hd, text=f"{self.game_name} hasn't started yet, so nothing in {'these' if n > 1 else 'it'} has run.",
                 bg=BG, fg=DIM, font=(FONT, 9), anchor="w").pack(anchor="w", pady=(2, 0))

        # scrollable list of cards
        holder = tk.Frame(win, bg=BG)
        holder.pack(fill="both", expand=True, padx=20)
        canvas = tk.Canvas(holder, bg=BG, highlightthickness=0, width=560)
        inner = tk.Frame(canvas, bg=BG)
        wid = canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(wid, width=e.width))
        canvas.pack(side="left", fill="both", expand=True)

        for p in problems:
            color = {"malicious": RED, "suspicious": AMBER}.get(p.verdict, BLUE)
            label = {"malicious": "MALICIOUS", "suspicious": "SUSPICIOUS"}.get(p.verdict, "GAME FILES")
            card = tk.Frame(inner, bg=CARD, highlightthickness=0)
            card.pack(fill="x", pady=5)
            tk.Frame(card, bg=color, width=4).pack(side="left", fill="y")
            body = tk.Frame(card, bg=CARD)
            body.pack(side="left", fill="x", expand=True, padx=12, pady=10)
            line = tk.Frame(body, bg=CARD)
            line.pack(fill="x")
            tk.Label(line, text=label, bg=color, fg="#10161e", font=(FONT, 8, "bold"), padx=6).pack(side="left")
            tk.Label(line, text=f"  {p.title}", bg=CARD, fg=FG, font=(FONT, 10, "bold"), anchor="w").pack(side="left")
            tk.Label(body, text=p.where, bg=CARD, fg=DIM, font=(FONT, 8), anchor="w", justify="left",
                     wraplength=500).pack(anchor="w", pady=(2, 4))
            for desc, f in p.reasons[:4]:
                t = f"•  {desc}" + (f"   ({f})" if f else "")
                tk.Label(body, text=t, bg=CARD, fg=FG, font=(FONT, 9), anchor="w", justify="left",
                         wraplength=500).pack(anchor="w")
            if len(p.reasons) > 4:
                tk.Label(body, text=f"…and {len(p.reasons) - 4} more", bg=CARD, fg=DIM, font=(FONT, 8)).pack(anchor="w")
            foot = tk.Frame(body, bg=CARD)
            foot.pack(fill="x", pady=(6, 0))
            if p.note:
                tk.Label(foot, text=p.note, bg=CARD, fg=DIM, font=(FONT, 8), anchor="w", justify="left",
                         wraplength=380).pack(side="left")
            if p.link:
                lk = tk.Label(foot, text="Workshop page", bg=CARD, fg=BLUE, font=(FONT, 8, "underline"),
                              cursor="hand2")
                lk.pack(side="right")
                lk.bind("<Button-1>", lambda _e, u=p.link: webbrowser.open(u))
            if p.can_allow:
                v = tk.BooleanVar(value=False)
                allow_vars[p.key] = v
                tk.Checkbutton(body, text="I trust this version: load it anyway", variable=v, bg=CARD, fg=FG,
                               selectcolor=BG, activebackground=CARD, activeforeground=FG, font=(FONT, 9),
                               command=lambda: refresh()).pack(anchor="w", pady=(6, 0))

        btns = tk.Frame(win, bg=BG)
        btns.pack(fill="x", padx=20, pady=(10, 18))

        def done(action):
            ans.action = action
            ans.allow = {k for k, v in allow_vars.items() if v.get()}
            win.destroy()

        def button(parent, text, cmd, primary=False):
            b = tk.Button(parent, text=text, command=cmd, font=(FONT, 10, "bold" if primary else "normal"),
                          bg=GREEN if primary else CARD, fg="#10161e" if primary else FG, relief="flat",
                          activebackground=HOT if primary else "#2a3a4d", padx=16, pady=6, cursor="hand2")
            return b

        button(btns, "Quit", lambda: done("quit")).pack(side="left")
        if any(p.verdict == "game" for p in problems):
            button(btns, "Repair game files", lambda: done("repair")).pack(side="left", padx=(8, 0))
        play = button(btns, "", lambda: done("play"), primary=True)
        play.pack(side="right")

        def refresh():
            blocked = sum(1 for p in problems if not (p.can_allow and allow_vars[p.key].get()))
            play.configure(text="Play" if blocked == 0 else
                           ("Play without it" if blocked == 1 else "Play without them"))

        refresh()
        tk.Label(win, text=f"Blocked mods are moved to {quarantine_dir}", bg=BG, fg=DIM, font=(FONT, 8)).pack(
            anchor="w", padx=20, pady=(0, 10))
        win.protocol("WM_DELETE_WINDOW", lambda: done("quit"))
        win.bind("<Escape>", lambda _e: done("quit"))
        win.update_idletasks()
        h = min(inner.winfo_reqheight(), 420)
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

    def alert(self, title: str, text: str, buttons: tuple[str, ...] = ("OK",)) -> str:
        """A simple message with buttons; returns the button pressed (the last one is the default)."""
        BG, CARD, FG, DIM, RED, AMBER, GREEN, BLUE, HOT = self.colors
        if headless():
            return os.environ.get("WG_GATE_ALERT", buttons[-1])
        self._tk()
        tk = self.tk
        win = tk.Toplevel(self.root, bg=BG)
        win.title(self.brand)
        win.attributes("-topmost", True)
        win.resizable(False, False)
        res = {"b": buttons[0]}
        top = tk.Frame(win, bg=BG)
        top.pack(fill="x", padx=20, pady=18)
        if self._logo:
            tk.Label(top, image=self._logo, bg=BG).pack(side="left", padx=(0, 14), anchor="n")
        box = tk.Frame(top, bg=BG)
        box.pack(side="left", fill="x", expand=True)
        tk.Label(box, text=title, bg=BG, fg=FG, font=(FONT, 12, "bold"), anchor="w", justify="left",
                 wraplength=420).pack(anchor="w")
        tk.Label(box, text=text, bg=BG, fg=FG, font=(FONT, 9), anchor="w", justify="left",
                 wraplength=420).pack(anchor="w", pady=(6, 0))
        row = tk.Frame(win, bg=BG)
        row.pack(fill="x", padx=20, pady=(0, 18))

        def pick(b):
            res["b"] = b
            win.destroy()

        for i, b in enumerate(reversed(buttons)):
            primary = i == 0
            tk.Button(row, text=b, command=lambda b=b: pick(b), font=(FONT, 10, "bold" if primary else "normal"),
                      bg=GREEN if primary else CARD, fg="#10161e" if primary else FG, relief="flat", padx=14, pady=5,
                      cursor="hand2").pack(side="right", padx=(8, 0))
        win.protocol("WM_DELETE_WINDOW", lambda: pick(buttons[0]))
        win.update_idletasks()
        self._place(win, 540, win.winfo_reqheight())
        win.deiconify()
        win.focus_force()
        self.root.wait_window(win)
        return res["b"]
