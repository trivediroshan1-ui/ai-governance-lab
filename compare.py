#!/usr/bin/env python3
"""Runs the round-two guardrail cases on several detectors and prints one
table: each variant down the side, each detector across the top.

    python3 compare.py v1 v2
    python3 compare.py v2 "external:python3 adapters/presidio_cmd.py"

ok = did the right thing (caught it; or left harmless text alone)
MISS = did not    n/a = the tool never claimed that job
"""
from __future__ import annotations
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from lab import detectors  # noqa: E402
from lab.cases_r2 import CASES, JOBS  # noqa: E402


def main(names: list[str]) -> None:
    dets = [detectors.get(n) for n in names]
    header = ["Case", "Variant"] + [d.name for d in dets]
    rows = []
    for cid, fn in CASES.items():
        results = [fn(d)[1]["ok"] for d in dets]
        for variant in results[0]:
            cells = []
            for d, res in zip(dets, results):
                if not (JOBS[cid] & d.supports):
                    cells.append("n/a")
                else:
                    cells.append("ok" if res.get(variant) else "MISS")
            rows.append([cid, variant] + cells)
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(r) + " |" for r in rows]
    scored = {d.name: [r[2 + i] for r in rows if r[2 + i] != "n/a"] for i, d in enumerate(dets)}
    lines += ["", "Handled correctly (of the variants each tool claims to cover):"]
    lines += [f"- {n}: {sum(c == 'ok' for c in cs)} of {len(cs)}" for n, cs in scored.items()]
    text = "\n".join(lines) + "\n"
    out = ROOT / "results" / "round-2"
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"compare-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.md"
    path.write_text(text)
    print(text)
    print(f"saved to {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main(sys.argv[1:] or ["v1", "v2"])
