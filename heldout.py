#!/usr/bin/env python3
"""Scores filters on the variants you wrote yourself (cases/held-out.json).

    python3 heldout.py v1 v2 v3
    python3 heldout.py v1 v2 v3 --file held-out-draft-by-claude.json

Write your items and commit the file BEFORE running this, so nobody (including
the author of the filters) can say the filters were tuned to them. Items
marked "example" are skipped.
"""
from __future__ import annotations
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from lab import detectors  # noqa: E402


def right(item, r) -> bool:
    if item["should"] == "catch":
        return bool(r.findings)
    if item["should"] == "flag":
        return bool(r.injection)
    return not r.findings and not r.injection          # leave


def main(names, file="held-out.json"):
    spec = json.loads((ROOT / "cases" / file).read_text())
    items = [i for i in spec["items"] if not i.get("example")]
    if not items:
        raise SystemExit("No scored items yet. Replace the examples in cases/held-out.json with your own variants.")
    dets = [detectors.get(n) for n in names]
    lines = ["| ID | Should | Text | " + " | ".join(d.name for d in dets) + " |", "|---|---|---|" + "---|" * len(dets)]
    tally = {d.name: 0 for d in dets}
    for it in items:
        cells = []
        for d in dets:
            ok = right(it, d.check(it["text"]))
            tally[d.name] += ok
            cells.append("ok" if ok else "MISS")
        lines.append(f"| {it['id']} | {it['should']} | {it['text'][:60].replace('|', '/')} | " + " | ".join(cells) + " |")
    lines += ["", f"Right, out of {len(items)}:"] + [f"- {n}: {t}" for n, t in tally.items()]
    text = "\n".join(lines) + "\n"
    out = ROOT / "results" / "held-out"
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"held-out-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.md"
    path.write_text(text)
    print(text)
    print(f"saved to {path.relative_to(ROOT)}")


if __name__ == "__main__":
    args = sys.argv[1:]
    file = "held-out.json"
    if "--file" in args:
        i = args.index("--file")
        file = args[i + 1]
        del args[i:i + 2]
    main(args or ["v1", "v2", "v3"], file)
