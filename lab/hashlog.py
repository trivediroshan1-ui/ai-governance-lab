from __future__ import annotations
"""An append-only decision log where every line carries the hash of the line
before it. Changing, removing or reordering any line breaks the chain from
that point, and verify() says where."""
import hashlib
import json

GENESIS = "0" * 64


def _digest(prev: str, body: dict) -> str:
    raw = prev + json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


class HashLog:
    def __init__(self):
        self.lines: list[dict] = []

    def append(self, event: dict) -> dict:
        prev = self.lines[-1]["hash"] if self.lines else GENESIS
        body = {"seq": len(self.lines) + 1, **event}
        line = {"body": body, "prev": prev, "hash": _digest(prev, body)}
        self.lines.append(line)
        return line

    def verify(self) -> tuple[bool, int | None]:
        """(True, None) if intact, else (False, the first bad line number)."""
        prev = GENESIS
        for i, line in enumerate(self.lines, start=1):
            if line["prev"] != prev or line["hash"] != _digest(prev, line["body"]):
                return False, i
            prev = line["hash"]
        return True, None

    def events(self, **match) -> list[dict]:
        return [l["body"] for l in self.lines if all(l["body"].get(k) == v for k, v in match.items())]
