"""Finding Workshop items: newest uploads, recent updates, and item details.

No Steam API key is needed. Listing reads the JSON Steam embeds in the public Workshop browse page; details come
from ISteamRemoteStorage/GetPublishedFileDetails, which is keyless. With STEAM_WEB_API_KEY set, listing uses
IPublishedFileService/QueryFiles instead and falls back to the page if that fails.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, asdict

import requests

log = logging.getLogger(__name__)

UA = "WorkshopGuard/1.0 (+https://github.com/CammyCodes/WorkshopGuard)"
BROWSE_URL = "https://steamcommunity.com/workshop/browse/"
DETAILS_URL = "https://api.steampowered.com/ISteamRemoteStorage/GetPublishedFileDetails/v1/"
QUERY_URL = "https://api.steampowered.com/IPublishedFileService/QueryFiles/v1/"
SSR_RE = re.compile(r'<script type="application/json" id="valve-ssr-data"[^>]*>(.*?)</script>', re.S)

# browse sort -> IPublishedFileService query_type
SORTS = {"mostrecent": 1, "lastupdated": 21}


@dataclass
class Item:
    appid: int
    id: str
    title: str = ""
    creator: str = ""
    time_created: int = 0
    time_updated: int = 0
    file_size: int = 0
    banned: bool = False
    ban_reason: str = ""
    preview_url: str = ""

    @property
    def url(self) -> str:
        return f"https://steamcommunity.com/sharedfiles/filedetails/?id={self.id}"

    def to_dict(self) -> dict:
        return asdict(self)


class SteamError(RuntimeError):
    pass


_session = requests.Session()
_session.headers["User-Agent"] = UA


def _get(url: str, **kw) -> requests.Response:
    for attempt in range(4):
        try:
            r = _session.get(url, timeout=30, **kw)
            if r.status_code == 429 or r.status_code >= 500:
                raise SteamError(f"HTTP {r.status_code}")
            r.raise_for_status()
            return r
        except (requests.RequestException, SteamError) as e:
            wait = 5 * 2 ** attempt
            log.warning("GET %s failed (%s), retrying in %ss", url.split("?")[0], e, wait)
            time.sleep(wait)
    raise SteamError(f"giving up on {url}")


def _from_result(appid: int, r: dict) -> Item:
    return Item(
        appid=int(r.get("consumer_appid") or r.get("consumer_app_id") or appid),
        id=str(r["publishedfileid"]),
        title=r.get("title", ""),
        creator=str(r.get("creator", "")),
        time_created=int(r.get("time_created") or 0),
        time_updated=int(r.get("time_updated") or 0),
        file_size=int(r.get("file_size") or 0),
        banned=bool(r.get("banned")),
        ban_reason=r.get("ban_reason") or "",
        preview_url=r.get("preview_url") or "",
    )


def _walk_queries(node, out: list):
    """Find react-query results inside Steam's SSR payload (some values are JSON-in-a-string)."""
    if isinstance(node, str):
        if node[:1] in "{[" and "publishedfileid" in node:
            try:
                node = json.loads(node)
            except ValueError:
                return
        else:
            return
    if isinstance(node, dict):
        state = node.get("state")
        key = node.get("queryKey")
        if isinstance(state, dict) and isinstance(key, list) and key and key[0] == "workshop_browse":
            data = state.get("data")
            if isinstance(data, dict) and "results" in data:
                out.append(data)
        for v in node.values():
            _walk_queries(v, out)
    elif isinstance(node, list):
        for v in node:
            _walk_queries(v, out)


def parse_browse_html(appid: int, html: str) -> tuple[list[Item], int]:
    """Return (items, total_count) from a Workshop browse page."""
    m = SSR_RE.search(html)
    if not m:
        raise SteamError("Workshop page layout changed: no valve-ssr-data block. Set STEAM_WEB_API_KEY as a fallback.")
    found: list[dict] = []
    _walk_queries(json.loads(m.group(1)), found)
    if not found:
        raise SteamError("Workshop page layout changed: no workshop_browse results found.")
    data = found[0]
    return [_from_result(appid, r) for r in data["results"]], int(data.get("total_count") or 0)


def browse_page(appid: int, sort: str, page: int, api_key: str = "") -> tuple[list[Item], int]:
    """One page of items, newest first (sort = mostrecent | lastupdated)."""
    if api_key:
        try:
            return _query_files(appid, sort, page, api_key)
        except Exception as e:  # noqa: BLE001 - fall back to the public page
            log.warning("QueryFiles failed (%s); using the public Workshop page", e)
    r = _get(BROWSE_URL, params={
        "appid": appid, "browsesort": sort, "actualsort": sort, "section": "readytouseitems",
        "p": page, "numperpage": 30,
    })
    return parse_browse_html(appid, r.text)


def _query_files(appid: int, sort: str, page: int, api_key: str) -> tuple[list[Item], int]:
    r = _get(QUERY_URL, params={
        "key": api_key, "appid": appid, "query_type": SORTS[sort], "page": page, "numperpage": 30,
        "return_metadata": "true", "return_details": "true",
    })
    resp = r.json().get("response", {})
    return [_from_result(appid, x) for x in resp.get("publishedfiledetails", [])], int(resp.get("total", 0))


def iter_items(appid: int, sort: str, max_pages: int | None, api_key: str = "", delay: float = 1.5):
    """Yield items page by page. max_pages=None walks the whole Workshop."""
    page = 1
    while True:
        items, total = browse_page(appid, sort, page, api_key)
        if not items:
            return
        yield from items
        pages = (total + 29) // 30
        if page >= pages or (max_pages is not None and page >= max_pages):
            return
        page += 1
        time.sleep(delay)


def details(ids: list[str], appid: int = 0) -> list[Item]:
    """Fresh details for up to ~100 items per call. Missing/deleted items are left out."""
    out: list[Item] = []
    for i in range(0, len(ids), 100):
        chunk = ids[i:i + 100]
        data = {"itemcount": len(chunk)}
        for n, x in enumerate(chunk):
            data[f"publishedfileids[{n}]"] = x
        r = _session.post(DETAILS_URL, data=data, timeout=30)
        r.raise_for_status()
        for d in r.json().get("response", {}).get("publishedfiledetails", []):
            if d.get("result") == 1:
                out.append(_from_result(appid, d))
    return out
