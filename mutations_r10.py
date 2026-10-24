#!/usr/bin/env python3
"""Round ten check on the tests themselves: switch one control off at a time in a
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
S = "lab/sessions.py"
MUTATIONS = [
    ("C1", "the check of the caller's key proof is skipped", S, [('if prf is None or key is None or not hmac.compare_digest(prf, proof(key, token, body)):', 'if False:')]),
    ("C3", "the app throws away revoke signals", S, [('if self.signals == "none":\n            return "ignored"', 'if True:\n            return "ignored"')]),
    ("C4", "the app does not check who signed a signal", S, [('if self.signals == "signed" and not self.idp.check_event(env):', 'if False:')]),
    ("C5", "the app stops comparing event times", S, [('if self.ordering == "time" and old and ev["at"] < old[0]:', 'if False:')]),
    ("C6", "the field-by-field update is replaced by a whole-record replace", S, [('if mode == "patch":\n            self.patch(uid, {"title": title})', 'if False:\n            pass')]),
    ("C7", "the fresh-joiner flow restores the old account", S, [('if mode == "restore":', 'if True:')]),
    ("C8", "matching by ID falls back to matching by name", S, [('k = rec["name"] if match == "name" else rec["id"]', 'k = rec["name"]')]),
    ("C9", "the required end date is ignored", S, [('if require_end:', 'if False:')]),
    ("C10", "break-glass use sends no alert", S, [('if self.alert:', 'if False:')]),
    ("C10", "the break-glass password is not changed at check-in", S, [('if self.rotate:', 'if False:')]),
    ("C11", "the log keeps names inline instead of a pseudonym", S, [('if self.pseudo:\n            pid', 'if False:\n            pid')]),
    ("C12", "the app does not check its own clock", S, [('if self.drift_limit is not None and', 'if False and')]),
]
RUN = "import json,sys\nfrom lab import cases_r10\ntry:\n    print(json.dumps(cases_r10.CASES[sys.argv[1]](None)[0]))\nexcept Exception as e:\n    print(json.dumps('error: '+type(e).__name__))\n"


def run_case(src: Path, cid: str) -> str:
    out = subprocess.run([sys.executable, "-c", RUN, cid], cwd=src, capture_output=True, text=True, timeout=120)
    return json.loads(out.stdout.strip().splitlines()[-1])


def main() -> int:
    spec = {c["id"]: c for c in json.loads((ROOT / "cases" / "round-10.json").read_text())["cases"]}
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
    out = ROOT / "results" / "round-10"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{stamp}-mutations.json").write_text(json.dumps(rows, indent=2) + "\n")
    lines = ["# Round ten: does each case notice when its control is switched off?", "",
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
