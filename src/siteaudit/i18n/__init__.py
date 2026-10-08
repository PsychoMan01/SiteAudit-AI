"""Message catalogues (English first, Portuguese second).

Keys are dotted paths into `<locale>.json`. Missing keys fall back to English, then to the key itself, so a
missing translation is visible in tests rather than silently mixing languages.
"""

from __future__ import annotations

import json
import string
from functools import cache
from pathlib import Path
from typing import Any

LOCALES = ("en", "pt")
DEFAULT_LOCALE = "en"
_DIR = Path(__file__).parent


@cache
def _catalog(locale: str) -> dict[str, str]:
    data = json.loads((_DIR / f"{locale}.json").read_text(encoding="utf-8"))
    flat: dict[str, str] = {}

    def walk(prefix: str, node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                walk(f"{prefix}.{k}" if prefix else k, v)
        else:
            flat[prefix] = str(node)

    walk("", data)
    return flat


def keys(locale: str) -> set[str]:
    return set(_catalog(locale))


class _SafeDict(dict[str, Any]):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def _fmt_value(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    if value is None:
        return "—"
    return str(value)


def t(locale: str, key: str, **params: Any) -> str:
    locale = locale if locale in LOCALES else DEFAULT_LOCALE
    text = _catalog(locale).get(key) or _catalog(DEFAULT_LOCALE).get(key)
    if text is None:
        return key
    if params:
        formatter = string.Formatter()
        return formatter.vformat(text, (), _SafeDict({k: _fmt_value(v) for k, v in params.items()}))
    return text


def tn(locale: str, key: str, n: int, **params: Any) -> str:
    """Plural-aware lookup: uses `<key>_one` when n == 1 and that key exists."""
    if n == 1 and has(locale, key + "_one"):
        return t(locale, key + "_one", n=n, **params)
    return t(locale, key, n=n, **params)


def has(locale: str, key: str) -> bool:
    return key in _catalog(locale if locale in LOCALES else DEFAULT_LOCALE)


def pick_locale(accept_language: str | None, explicit: str | None = None) -> str:
    if explicit in LOCALES:
        return explicit
    for part in (accept_language or "").split(","):
        tag = part.split(";", 1)[0].strip().lower()[:2]
        if tag in LOCALES:
            return tag
    return DEFAULT_LOCALE
