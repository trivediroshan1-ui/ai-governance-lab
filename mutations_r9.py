#!/usr/bin/env python3
"""Round nine check on the tests themselves: switch one control off at a time in a
copy of the code (each run in its own process) and see whether the matching case
stops passing. Run: python3 mutations_r9.py"""
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
R, A = "lab/rag.py", "lab/actions.py"
MUTATIONS = [
    ("Q1", "the no-check and prompt-only modes are given the permission filter", R, [('if self.perm == "none" or self.perm == "prompt":', 'if False:')]),
    ("Q2", "the no-check and prompt-only modes are given the permission filter", R, [('if self.perm == "none" or self.perm == "prompt":', 'if False:')]),
    ("Q3", "the permission filter lets every chunk through", R, [('return team == chunk["team"]', 'return True')]),
    ("Q4", "the live check reads the stale index copy instead of the directory", R, [('team = self.staff[user]["team"] if self.perm == "pre_live" else self.index_teams[user]', 'team = self.index_teams[user]')]),
    ("Q4", "a refresh does not recopy permissions", R, [('self.index_teams = {k: v["team"] for k, v in self.staff.items()}   # permissions copied at index time', 'self.index_teams = getattr(self, "index_teams", {k: v["team"] for k, v in self.staff.items()})')]),
    ("Q5", "unknown actions are no longer rejected by the gateway (it then fails instead of accepting)", A, [('        if spec is None:\n            self._record("request_rejected", agent=agent, request=rid, why="unknown action")', '        if False:\n            self._record("request_rejected", agent=agent, request=rid, why="unknown action")')]),
    # second, cleaner checks added 25 Oct for the three weakest rows (Q1, Q2, Q5). The first checks above are kept.
    ("Q1", "the model no longer repeats text from restricted chunks it was handed (the careless-model assumption removed)", R, [('text = " ".join(context)                                  # the careless model repeats what it sees', 'text = " ".join(t for t, c in zip(context, allowed) if c["team"] is None)')]),
    ("Q2", "the model obeys the 'do not reveal' label (the assumption that it ignores the label removed)", R, [('text = " ".join(context)                                  # the careless model repeats what it sees', 'text = " ".join(t for t in context if not t.startswith("[restricted"))')]),
    ("Q5", "the gateway lets an unlisted action through and skips the shape check (a second layer, the executor, is still in place)", A, [('        if spec is None:\n            self._record("request_rejected", agent=agent, request=rid, why="unknown action")\n            return self._reply(outcome="rejected", reason="action must be one of the listed actions")', '        if spec is None:\n            spec = {"scope": "idm.user.create", "approval": False, "limit": 99}'), ('        bad = validate(req)\n', '        bad = None\n')]),
    ("Q6", "every user shares one cache entry", R, [('key = (query,) if self.cache_mode == "shared" else (query, user)', 'key = (query,)')]),
    ("Q7", "sources always list every match", R, [('shown = matches if self.sources_mode == "all_matches" else allowed', 'shown = matches')]),
    ("Q8", "personal numbers are not masked at ingestion", R, [('text = AADHAAR_RE.sub("[AADHAAR]", d["text"]) if self.mask else d["text"]', 'text = d["text"]')]),
    ("Q9", "a rebuild of the index reads the old document list, not the store", R, [('for d in self.source:\n            text', 'for d in DOCS:\n            text')]),
    ("Q11", "the trace always keeps the chunk text", R, [('**({"text": c["text"]} if self.trace_mode == "full" else {})', '**{"text": c["text"]}')]),
    ("Q12", "the assistant always acts with the person's permissions", R, [('if not self.on_behalf:\n            return True', 'if False:\n            return True')]),
]
RUN = "import json,sys\nfrom lab import cases_r9\ntry:\n    print(json.dumps(cases_r9.CASES[sys.argv[1]](None)[0]))\nexcept Exception as e:\n    print(json.dumps('error: '+type(e).__name__))\n"


def run_case(src: Path, cid: str) -> str:
    out = subprocess.run([sys.executable, "-c", RUN, cid], cwd=src, capture_output=True, text=True, timeout=120)
    return json.loads(out.stdout.strip().splitlines()[-1])


def main() -> int:
    spec = {c["id"]: c for c in json.loads((ROOT / "cases" / "round-9.json").read_text())["cases"]}
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
    out = ROOT / "results" / "round-9"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{stamp}-mutations.json").write_text(json.dumps(rows, indent=2) + "\n")
    lines = ["# Round nine: does each case notice when its control is switched off?", "",
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
