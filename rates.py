#!/usr/bin/env python3
"""Catch rate and false-alarm rate on the 200 labelled samples, for any
detector. This is how the lab compares itself with other tools (plan cases
G12 and G13).

    python3 rates.py v1 v2
    python3 rates.py v2 "external:python3 adapters/presidio_cmd.py"

A tool is only scored on what it claims to do. A PII library that never
promised to find secrets will show a low catch rate on the secret samples:
read the by-kind table, not just the headline number.
"""
from __future__ import annotations
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from lab import detectors, testset  # noqa: E402


def main(names):
    samples = testset.build()
    results = {}
    for n in names:
        d = detectors.get(n)
        results[d.name] = (testset.score(d, samples), d.supports)
    lines = ["| Detector | Catch rate | False-alarm rate | Claims |", "|---|---|---|---|"]
    for name, (r, sup) in results.items():
        lines.append(f"| {name} | {r['caught']} of {r['n_sensitive']} ({r['catch_rate']:.0%}) | "
                     f"{r['false_alarms']} of {r['n_harmless']} ({r['false_alarm_rate']:.0%}) | {', '.join(sorted(sup))} |")
    kinds = list(max((r["by_kind"] for r, _ in results.values()), key=len))
    lines += ["", "Caught, by kind of sensitive data:", "", "| Kind | " + " | ".join(results) + " |", "|---|" + "---|" * len(results)]
    lines += [f"| {k} | " + " | ".join(r["by_kind"].get(k, "n/a") for r, _ in results.values()) + " |" for k in kinds]
    lines += ["", "False alarms, by kind of harmless text:", ""]
    for name, (r, _) in results.items():
        lines.append(f"- {name}: " + (", ".join(f"{k} ({v})" for k, v in r["false_alarm_kinds"].items()) or "none"))
    text = "\n".join(lines) + "\n"
    out = ROOT / "results" / "round-3"
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"rates-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.md"
    path.write_text(text)
    print(text)
    print(f"saved to {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main(sys.argv[1:] or ["v1", "v2"])
