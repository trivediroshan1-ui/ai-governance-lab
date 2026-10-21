"""The guardrail filter: finds secrets and Indian personal data in a prompt,
masks them before the prompt reaches a model, and flags likely prompt
injection. Version 1 is deliberately plain: regular expressions, the Aadhaar
checksum, Luhn for cards, a little normalising, and a short list of
injection phrases. The lab measures what that catches and what it misses.
"""
import base64
import re
from dataclasses import dataclass, field

from . import ids

DEVANAGARI_DIGITS = str.maketrans("०१२३४५६७८९", "0123456789")

SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    "api_key": re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
}
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
PHONE = re.compile(r"(?<!\d)(?:\+91[\s-]?|0)?([6-9]\d{9})(?!\d)")
# 12 digits, allowing a space or hyphen after each group of four.
AADHAAR_LIKE = re.compile(r"(?<!\d)([2-9]\d{3})[\s-]?(\d{4})[\s-]?(\d{4})(?!\d)")
CARD_LIKE = re.compile(r"(?<!\d)(\d{4})[\s-]?(\d{4})[\s-]?(\d{4})[\s-]?(\d{4})(?!\d)")
BASE64_BLOB = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}")

INJECTION_PHRASES = [
    "ignore your rules", "ignore previous instructions", "ignore all previous", "disregard the above",
    "you are now", "send this file", "reveal your system prompt", "do not tell the user",
]


@dataclass
class Finding:
    kind: str
    value: str


@dataclass
class Result:
    masked: str
    findings: list[Finding] = field(default_factory=list)
    injection: bool = False

    @property
    def kinds(self) -> set[str]:
        return {f.kind for f in self.findings}

    @property
    def personal(self) -> bool:
        return bool(self.kinds & {"aadhaar", "pan", "card", "phone", "email"})

    @property
    def secret(self) -> bool:
        return bool(self.kinds & set(SECRET_PATTERNS))


def _scan(text: str, out: list[Finding]) -> str:
    for kind, rx in SECRET_PATTERNS.items():
        for m in rx.finditer(text):
            out.append(Finding(kind, m.group(0)))
        text = rx.sub(f"[{kind.upper()}]", text)

    def aadhaar(m):
        digits = "".join(m.groups())
        if ids.aadhaar_valid(digits):
            out.append(Finding("aadhaar", digits))
            return "[AADHAAR]"
        return m.group(0)

    def card(m):
        digits = "".join(m.groups())
        if ids.luhn_valid(digits):
            out.append(Finding("card", digits))
            return "[CARD]"
        return m.group(0)

    text = CARD_LIKE.sub(card, text)
    text = AADHAAR_LIKE.sub(aadhaar, text)
    for m in ids.PAN_RE.finditer(text):
        out.append(Finding("pan", m.group(0)))
    text = ids.PAN_RE.sub("[PAN]", text)
    for m in EMAIL.finditer(text):
        out.append(Finding("email", m.group(0)))
    text = EMAIL.sub("[EMAIL]", text)
    for m in PHONE.finditer(text):
        out.append(Finding("phone", m.group(1)))
    text = PHONE.sub("[PHONE]", text)
    return text


def check(text: str) -> Result:
    findings: list[Finding] = []
    normal = text.translate(DEVANAGARI_DIGITS)
    masked = _scan(normal, findings)
    # Secrets or numbers hidden in base64: decode, scan, and mask the blob if
    # anything was inside.
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
    lowered = normal.lower()
    injection = any(p in lowered for p in INJECTION_PHRASES)
    return Result(masked=masked, findings=findings, injection=injection)
