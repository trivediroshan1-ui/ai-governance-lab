#!/usr/bin/env python3
"""Round thirteen check on the tests themselves: switch one control off at a time in a
copy of the code (each run in its own process) and see whether the matching case
stops passing. Run: python3 mutations_r13.py"""
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
S = "lab/rag.py"
MUTATIONS = [
    ("S1", "permissions are not checked at all, so a meaning match reaches the support agent", S, [('if self.perm == "none" or self.perm == "prompt":', 'if True:')]),
    ("S2", "the source list shows every match, not only what the person may see", S, [('shown = matches if self.sources_mode == "all_matches" else allowed', 'shown = matches')]),
    ("S3", "the permission filter runs after the ranking, not before", S, [('if self.rank_filter == "before":', 'if False:')]),
    ("S4", "ID numbers are not masked when documents are indexed", S, [('text = AADHAAR_RE.sub("[AADHAAR]", d["text"]) if self.mask else d["text"]', 'text = d["text"]')]),
    ("S5", "permissions are read from the copy taken when documents were indexed", S, [('team = self.staff[user]["team"] if self.perm == "pre_live" else self.index_teams[user]', 'team = self.index_teams[user]')]),
]
RUN = "import json,sys\nfrom lab import cases_r13\ntry:\n    print(json.dumps(cases_r13.CASES[sys.argv[1]](None)[0]))\nexcept Exception as e:\n    print(json.dumps('error: '+type(e).__name__))\n"


def run_case(src: Path, cid: str) -> str:
    out = subprocess.run([sys.executable, "-c", RUN, cid], cwd=src, capture_output=True, text=True, timeout=120)
    return json.loads(out.stdout.strip().splitlines()[-1])


def main() -> int:
    spec = {c["id"]: c for c in json.loads((ROOT / "cases" / "round-13.json").read_text())["cases"]}
    rows = []
    for cid, what, rel, edits in MUTATIONS:
        with tempfile.TemporaryDirectory() as td:
            dst = Path(td) / "copy"
            shutil.copytree(ROOT / "lab", dst / "lab", ignore=shutil.ignore_patterns("__pycache__"))
            f = dst / rel
            text = f.read_text()
            for old, new in edits:
                assert text.count(old) == 1, f"text for {cid} ({what}) not found exactly once: {old}"
                text = text.replace(old, new)
            normal = run_case(ROOT, cid)
            f.write_text(text)
            after = run_case(dst, cid)
        rows.append({"case": cid, "switched_off": what, "expected": spec[cid]["expected"], "normal": normal, "with_control_off": after,
                     "case_notices": after != spec[cid]["expected"]})
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = ROOT / "results" / "round-13"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{stamp}-mutations.json").write_text(json.dumps(rows, indent=2) + "\n")
    lines = ["# Round thirteen: does each case notice when its control is switched off?", "",
             f"Run {stamp} UTC. One control at a time is removed from a copy of the code.", "",
             "| Case | Control switched off | Normal result | Result with control off | Case notices |", "|---|---|---|---|---|"]
    lines += [f"| {r['case']} | {r['switched_off']} | {r['normal']} | {r['with_control_off']} | {'yes' if r['case_notices'] else 'NO'} |" for r in rows]
    (out / f"{stamp}-mutations.md").write_text("\n".join(lines) + "\n")
    noticed = sum(r["case_notices"] for r in rows)
    print(f"{noticed} of {len(rows)} switched-off controls are noticed by their case")
    for r in rows:
        if not r["case_notices"]:
            print("  not noticed:", r["case"], r["switched_off"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
