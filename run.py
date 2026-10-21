from __future__ import annotations
#!/usr/bin/env python3
"""Runs the AI Governance Lab cases and writes the results.

    python3 run.py                 # round one, the real run
    python3 run.py --dry-run       # checks everything works; results go to results/dry-run/
    python3 run.py --only A1,G5    # just some cases

Each case's expected result is read from cases/round-<n>.json, which should
be committed before the run. The results file records that file's hash, so
anyone can check the guesses weren't changed after the fact.
"""
import argparse
import hashlib
import json
import platform
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from lab.cases import CASES  # noqa: E402

TRACKS = {"A": "AI use gateway", "G": "Guardrail filter", "I": "Agent identity and access", "E": "Audit evidence"}


def git_commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True,
                              check=True).stdout.strip()
    except Exception:
        return "not a git checkout"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, default=1)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--only", default="")
    ap.add_argument("--detector", default="v2", help="round 2 only: v1, v2 or external:<command>")
    args = ap.parse_args()

    detector = None
    if args.round >= 2:
        from lab import detectors
        import importlib
        CASES2 = importlib.import_module(f"lab.cases_r{args.round}").CASES
        detector = detectors.get(args.detector)
    cases_path = ROOT / "cases" / f"round-{args.round}.json"
    raw = cases_path.read_bytes()
    spec = json.loads(raw)
    only = {x.strip() for x in args.only.split(",") if x.strip()}

    started = time.perf_counter()
    rows = []
    for c in spec["cases"]:
        if only and c["id"] not in only:
            continue
        fn = (CASES2 if detector else CASES).get(c["id"])
        if fn is None:
            rows.append({**c, "actual": None, "verdict": "not run", "details": {"why": "no implementation yet"}})
            continue
        try:
            actual, details = fn(detector) if detector else fn()
            verdict = "as expected" if actual == c["expected"] else "different"
        except Exception as e:  # a crash is a result too
            actual, verdict = "error", "not run"
            details = {"error": f"{type(e).__name__}: {e}", "trace": traceback.format_exc(limit=3)}
        rows.append({**c, "actual": actual, "verdict": verdict, "details": details})
    seconds = time.perf_counter() - started

    counts = {}
    for r in rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    meta = {
        "kind": "dry run (not a lab result)" if args.dry_run else f"round {args.round}",
        "run_at_utc": stamp, "seconds": round(seconds, 2), "python": platform.python_version(),
        "machine": f"{platform.system()} {platform.machine()}", "commit": git_commit(),
        "detector": detector.name if detector else "built-in", "cases_file": cases_path.name, "cases_sha256": hashlib.sha256(raw).hexdigest(), "counts": counts,
        "data": "Kaveri Finance is made up. Every name and ID number is invented test data.",
    }
    outdir = ROOT / "results" / ("dry-run" if args.dry_run else f"round-{args.round}")
    outdir.mkdir(parents=True, exist_ok=True)
    base = outdir / (f"{stamp}-{detector.name}" if detector else f"{stamp}")
    base.with_suffix(".json").write_text(json.dumps({"meta": meta, "results": rows}, indent=2, ensure_ascii=False,
                                                    default=str) + "\n")

    lines = [f"# AI Governance Lab: {meta['kind']}", "",
             f"Run {stamp} UTC on {meta['machine']}, Python {meta['python']}, commit {meta['commit']}, "
             f"{meta['seconds']} s. Detector: {meta['detector']}. Cases file sha256 {meta['cases_sha256'][:16]}.", "",
             "Verdicts: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())), ""]
    for t, name in TRACKS.items():
        part = [r for r in rows if r["track"] == t]
        if not part:
            continue
        lines += [f"## Track {t}: {name}", "", "| ID | Case | Expected | Actual | Verdict |", "|---|---|---|---|---|"]
        lines += [f"| {r['id']} | {r['title']} | {r['expected']} | {r['actual']} | {r['verdict']} |" for r in part]
        lines.append("")
    lines.append(meta["data"])
    base.with_suffix(".md").write_text("\n".join(lines) + "\n")

    print(f"{meta['kind']}: {len(rows)} cases in {meta['seconds']} s -> {base.relative_to(ROOT)}.json")
    print("  " + ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())))
    return 0 if "not run" not in counts else 1


if __name__ == "__main__":
    sys.exit(main())
