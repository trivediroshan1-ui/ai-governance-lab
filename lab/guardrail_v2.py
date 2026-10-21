"""Guardrail filter, version 2.

Same job as version 1 and still plain pattern matching, with no model in it.
It fixes the gaps round one found (connection strings, lower-case PAN, phone
numbers split 5 and 5, reworded or line-broken injection) and adds a few
things real prompts need: full-width and zero-width characters, tokens that
look like JWTs, a short look back across messages. Hinglish and spelled-out
numbers are still open on purpose, so round two has something left to find.
"""
from __future__ import annotations

import base64
import re
import unicodedata

from . import ids
from .guardrail import (BASE64_BLOB, DEVANAGARI_DIGITS, EMAIL, Finding, Result as _ResultV1, SECRET_PATTERNS)

ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u200e\u200f\u2060\ufeff"), None)

SECRETS_V2 = dict(SECRET_PATTERNS)
SECRETS_V2.update({
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)"),
    "url_with_password": re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:\S+@[\w.-]+"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    "assigned_secret": re.compile(
        r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key)\s*(?:=|:\s*[\"'])\s*[\"']?[^\s\"']{6,}"),
})

class Result(_ResultV1):
    """Same as version 1, but knows the extra secret kinds (and "secret", which
    is what an outside tool reports)."""

    @property
    def secret(self) -> bool:
        return bool(self.kinds & (set(SECRETS_V2) | {"secret"}))


PAN_V2 = re.compile(r"\b[A-Za-z]{3}[PCHFATBLJGpchfatblj][A-Za-z]\d{4}[A-Za-z]\b")
PHONE_V2 = re.compile(r"(?<!\d)(?:\(?\+91\)?[\s-]?|0)?([6-9]\d{4}[\s-]?\d{5}|[6-9]\d{2}[\s-]?\d{3}[\s-]?\d{4})(?!\d)")
# 12 to 16 digits with a single space, dot or hyphen allowed between any two digits.
DIGIT_RUN = re.compile(r"(?<![\d])\d(?:[ .-]?\d){11,15}(?!\d)")

OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|forget|set aside|override|bypass|drop|skip)\b[^.\n]{0,40}?"
    r"\b(?:instructions?|rules?|guidance|guidelines?|prompt|directions?|above|previous|earlier|prior|system)\b")
HIDE = re.compile(r"\b(?:do not|don't|never)\s+(?:tell|inform|mention|show)\b[^.\n]{0,20}\b(?:user|them|anyone)\b")
REVEAL = re.compile(r"\b(?:reveal|print|repeat|show)\b[^.\n]{0,30}\b(?:system prompt|hidden prompt|your instructions)\b")
EXFIL = re.compile(r"\b(?:send|email|mail|forward|upload|post|leak)\b[^.\n]{0,60}?"
                   r"\b(?:file|attachment|document|data|secrets?|credentials?|keys?)\b[^.\n]{0,60}?(?:@|https?://)")
ROLE = re.compile(r"\byou are now\b|\bfrom now on,? you (?:are|will)\b|\bpretend (?:to be|you are)\b")
ADDRESSED_TO_AI = re.compile(r"\b(?:assistant|ai|model|agent|chatbot)\b")


def normalise(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH)
    return text.replace("\u00a0", " ").translate(DEVANAGARI_DIGITS)


def _scan(text: str, out: list[Finding]) -> str:
    for kind, rx in SECRETS_V2.items():
        for m in rx.finditer(text):
            out.append(Finding(kind, m.group(0)))
        text = rx.sub(f"[{kind.upper()}]", text)

    def digits(m):
        d = re.sub(r"\D", "", m.group(0))
        if len(d) == 12 and ids.aadhaar_valid(d):
            out.append(Finding("aadhaar", d))
            return "[AADHAAR]"
        if len(d) == 16 and ids.luhn_valid(d):
            out.append(Finding("card", d))
            return "[CARD]"
        return m.group(0)

    text = DIGIT_RUN.sub(digits, text)
    for m in PAN_V2.finditer(text):
        out.append(Finding("pan", m.group(0)))
    text = PAN_V2.sub("[PAN]", text)
    for m in EMAIL.finditer(text):
        out.append(Finding("email", m.group(0)))
    text = EMAIL.sub("[EMAIL]", text)
    for m in PHONE_V2.finditer(text):
        out.append(Finding("phone", re.sub(r"\D", "", m.group(1))))
    return PHONE_V2.sub("[PHONE]", text)


def looks_like_injection(text: str) -> bool:
    t = re.sub(r"<!--|-->", " ", text.lower())
    t = re.sub(r"\s+", " ", t)
    return bool(OVERRIDE.search(t) or HIDE.search(t) or REVEAL.search(t) or ROLE.search(t)
                or (EXFIL.search(t) and ADDRESSED_TO_AI.search(t)))


def check(text: str) -> Result:
    findings: list[Finding] = []
    normal = normalise(text)
    masked = _scan(normal, findings)
    for blob in set(BASE64_BLOB.findall(masked)):
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8")
        except Exception:
            continue
        inner: list[Finding] = []
        _scan(decoded, inner)
        if inner:
            findings.extend(Finding(f.kind + "_in_base64", f.value) for f in inner)
            masked = masked.replace(blob, "[ENCODED_SECRET]")
    return Result(masked=masked, findings=findings, injection=looks_like_injection(normal))


def check_session(messages: list[str], window: int = 5) -> Result:
    """Look at the last few messages together. Catches an Aadhaar number
    that was split across two messages by joining the digit groups."""
    recent = [normalise(m) for m in messages[-window:]]
    result = check(" ".join(recent))
    groups = [g for m in recent for g in re.findall(r"\d{4}", re.sub(r"(?<=\d)[ .-](?=\d)", "", m))]
    for i in range(len(groups) - 2):
        d = "".join(groups[i:i + 3])
        if ids.aadhaar_valid(d):
            result.findings.append(Finding("aadhaar", d))
            break
    return result
