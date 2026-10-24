"""Alerts: Discord webhook and/or a generic JSON webhook (Slack-compatible 'text' field included)."""

from __future__ import annotations

import logging

import requests

from .scan.model import SEVERITY_WEIGHT

log = logging.getLogger(__name__)
COLORS = {"malicious": 0xE5484D, "suspicious": 0xF5A524, "clean": 0x30A46C}
ICONS = {"malicious": "\U0001F6A8", "suspicious": "⚠️", "clean": "✅"}


def _top(findings: list[dict], n: int = 6) -> list[dict]:
    return sorted((f for f in findings if f["severity"] != "info"),
                  key=lambda f: -SEVERITY_WEIGHT[f["severity"]])[:n]


def build_payload(item: dict, game: str, verdict: str, score: int, findings: list[dict], *, is_test: bool,
                  previous: str | None, public_url: str) -> dict:
    url = f"https://steamcommunity.com/sharedfiles/filedetails/?id={item['id']}"
    creator = item.get("creator") or ""
    return {
        "event": "workshop_item_flagged",
        "test": is_test,
        "verdict": verdict,
        "previous_verdict": previous,
        "score": score,
        "game": game,
        "appid": item["appid"],
        "item_id": item["id"],
        "title": item.get("title", ""),
        "url": url,
        "creator": creator,
        "creator_url": f"https://steamcommunity.com/profiles/{creator}" if creator else "",
        "time_updated": item.get("time_updated"),
        "findings": _top(findings, 20),
        "dashboard": f"{public_url}/item/{item['appid']}/{item['id']}" if public_url else "",
    }


def discord_embed(p: dict) -> dict:
    lines = []
    for f in _top(p["findings"]):
        where = f" `{f['file'][:60]}`" if f.get("file") else ""
        lines.append(f"**{f['severity'].upper()}** {f['description']}{where}")
    desc = "\n".join(lines) or "No details."
    tag = "[TEST] " if p["test"] else ""
    title = f"{tag}{ICONS.get(p['verdict'], '')} {p['verdict'].upper()}: {p['title'][:180]}"
    fields = [
        {"name": "Game", "value": p["game"], "inline": True},
        {"name": "Score", "value": str(p["score"]), "inline": True},
    ]
    if p["creator_url"]:
        fields.append({"name": "Uploader", "value": f"[profile]({p['creator_url']})", "inline": True})
    if p["previous_verdict"] and p["previous_verdict"] != p["verdict"]:
        fields.append({"name": "Changed", "value": f"was {p['previous_verdict']} before this update", "inline": False})
    if p["dashboard"]:
        fields.append({"name": "Details", "value": p["dashboard"], "inline": False})
    footer = ("This is a TEST alert from WorkshopGuard's fake detection." if p["test"] else
              "WorkshopGuard: automated scan. Review before acting; report real malware to Valve from the item page.")
    return {
        "username": "WorkshopGuard",
        "embeds": [{"title": title[:256], "url": p["url"], "description": desc[:3900], "color": COLORS[p["verdict"]],
                    "fields": fields, "footer": {"text": footer}}],
        "allowed_mentions": {"parse": []},
    }


class Notifier:
    def __init__(self, discord_url: str = "", webhook_url: str = "", notify_on: set[str] | None = None,
                 public_url: str = ""):
        self.discord_url, self.webhook_url = discord_url, webhook_url
        self.notify_on = notify_on or {"malicious", "suspicious"}
        self.public_url = public_url
        self.sent: list[dict] = []  # last payloads, for the dashboard/selftest

    @property
    def enabled(self) -> bool:
        return bool(self.discord_url or self.webhook_url)

    def maybe_send(self, item: dict, game: str, verdict: str, score: int, findings: list[dict], *,
                   is_test: bool = False, previous: str | None = None) -> bool:
        if verdict not in self.notify_on:
            return False
        p = build_payload(item, game, verdict, score, findings, is_test=is_test, previous=previous,
                          public_url=self.public_url)
        self.sent = (self.sent + [p])[-50:]
        ok = True
        if self.discord_url:
            ok &= self._post(self.discord_url, discord_embed(p))
        if self.webhook_url:
            body = dict(p, text=f"{'[TEST] ' if is_test else ''}WorkshopGuard: {verdict.upper()} {p['title']} {p['url']}")
            ok &= self._post(self.webhook_url, body)
        log.info("Alert %s for %s %s (%s)", "sent" if ok else "FAILED", verdict, item["id"], p["title"])
        return ok

    @staticmethod
    def _post(url: str, body: dict) -> bool:
        try:
            r = requests.post(url, json=body, timeout=20)
            if r.status_code >= 300:
                log.warning("Webhook HTTP %s: %s", r.status_code, r.text[:200])
                return False
            return True
        except requests.RequestException as e:
            log.warning("Webhook failed: %s", e)
            return False
