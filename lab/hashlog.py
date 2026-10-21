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
    def __init__(self, retention_days: int = 180):
        self.lines: list[dict] = []
        self.base = GENESIS              # hash of the last pruned line, so the chain still checks
        self.retention_days = retention_days

    def append(self, event: dict) -> dict:
        prev = self.lines[-1]["hash"] if self.lines else self.base
        body = {"seq": self._next_seq, **event}
        line = {"body": body, "prev": prev, "hash": _digest(prev, body)}
        self.lines.append(line)
        return line

    def verify(self) -> tuple[bool, int | None]:
        """(True, None) if intact, else (False, the first bad line number)."""
        prev = self.base
        for i, line in enumerate(self.lines, start=1):
            if line["prev"] != prev or line["hash"] != _digest(prev, line["body"]):
                return False, i
            prev = line["hash"]
        return True, None

    def events(self, **match) -> list[dict]:
        return [l["body"] for l in self.lines if all(l["body"].get(k) == v for k, v in match.items())]

    @property
    def _next_seq(self) -> int:
        return (self.lines[-1]["body"]["seq"] + 1) if self.lines else self.pruned + 1

    pruned = 0

    def anchor(self) -> dict:
        """A short record of where the log ends. Kept somewhere else (printed,
        mailed, written to a second system), it lets you notice lines cut off the end."""
        return {"length": len(self.lines), "last_seq": self.lines[-1]["body"]["seq"] if self.lines else 0,
                "head": self.lines[-1]["hash"] if self.lines else self.base}

    def verify_against(self, anchor: dict) -> tuple[bool, str]:
        ok, bad = self.verify()
        if not ok:
            return False, f"chain broken at line {bad}"
        if not self.lines or self.lines[-1]["body"]["seq"] < anchor["last_seq"]:
            return False, "log is shorter than the anchor says"
        match = [l for l in self.lines if l["body"]["seq"] == anchor["last_seq"]]
        if not match or match[0]["hash"] != anchor["head"]:
            return False, "line at the anchor does not match"
        return True, "intact"

    def prune(self, now) -> int:
        """Remove lines older than the retention period, oldest first. Younger lines stay."""
        from datetime import datetime, timedelta
        cut = now - timedelta(days=self.retention_days)
        n = 0
        while self.lines and datetime.fromisoformat(self.lines[0]["body"]["at"]) < cut:
            self.base = self.lines[0]["hash"]
            self.pruned = self.lines[0]["body"]["seq"]
            self.lines.pop(0)
            n += 1
        return n
