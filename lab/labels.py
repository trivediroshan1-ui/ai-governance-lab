from __future__ import annotations
"""Labelling AI-made content (E12): a visible banner, signed metadata, and a
hash recorded at the time it was made. Plain HTML, so the lab can show what
survives an editor, a copy-paste, and someone deleting the banner."""
import hashlib
import hmac
import json
import re

KEY = b"lab-label-key (made up)"
META = re.compile(r'<meta name="ai-generated" content=\'(.*?)\'>')
SIG = re.compile(r'<meta name="ai-label-sig" content="(.*?)">')
BANNER = re.compile(r'<p class="ai-banner">.*?</p>')


def _sig(meta: str) -> str:
    return hmac.new(KEY, meta.encode(), hashlib.sha256).hexdigest()


def fingerprint(text: str) -> str:
    return hashlib.sha256(" ".join(text.split()).encode()).hexdigest()


def label(text: str, model: str, when: str, seen: set[str]) -> str:
    meta = json.dumps({"generator": model, "created": when, "ai": True}, sort_keys=True)
    seen.add(fingerprint(text))
    return (f'<!doctype html><meta name="ai-generated" content=\'{meta}\'>'
            f'<meta name="ai-label-sig" content="{_sig(meta)}">'
            f'<p class="ai-banner">Made with AI ({model}, {when})</p><div>{text}</div>')


def has_banner(html: str) -> bool:
    return bool(BANNER.search(html))


def metadata_state(html: str) -> str:
    m, s = META.search(html), SIG.search(html)
    if not m or not s:
        return "missing"
    return "ok" if hmac.compare_digest(s.group(1), _sig(m.group(1))) else "tampered"


def resave_keeping_meta(html: str) -> str:
    """An editor that tidies the file but keeps what it doesn't understand."""
    return re.sub(r">\s+<", "><", html.strip())


def resave_sanitiser(html: str) -> str:
    """A content system that strips meta tags it doesn't know. Many do."""
    return re.sub(r"<meta [^>]*>", "", html)


def visible_text(html: str) -> str:
    return re.sub(r"<[^>]+>", " ", html).strip()


def body_text(html: str) -> str:
    m = re.search(r"<div>(.*)</div>", html, re.S)
    return m.group(1) if m else ""
