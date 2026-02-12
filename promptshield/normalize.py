from __future__ import annotations

import base64
import html
import re
import unicodedata
from urllib.parse import unquote

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\ufeff"), None)
_WS_RE = re.compile(r"\s+")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]{24,}$")


def normalize_text(text: str) -> str:
    value = unicodedata.normalize("NFKC", text)
    value = html.unescape(value)
    value = value.translate(_ZERO_WIDTH)
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    return _WS_RE.sub(" ", value).strip()


def _try_decode_base64(text: str) -> str | None:
    candidate = text.strip()
    if len(candidate) % 4 != 0 or not _BASE64_RE.match(candidate):
        return None
    try:
        decoded = base64.b64decode(candidate, validate=True)
        value = decoded.decode("utf-8")
    except Exception:
        return None
    if not value.strip() or len(value) > 20000:
        return None
    return value


def build_scan_views(text: str) -> dict[str, str]:
    views: dict[str, str] = {
        "original": text,
        "normalized": normalize_text(text),
    }

    url_decoded = normalize_text(unquote(text))
    if url_decoded and url_decoded != views["normalized"]:
        views["url_decoded"] = url_decoded

    base64_decoded = _try_decode_base64(views["normalized"])
    if base64_decoded:
        views["base64_decoded"] = normalize_text(base64_decoded)

    return views
