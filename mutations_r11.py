#!/usr/bin/env python3
"""Round eleven check on the tests themselves: switch one control off at a time in a
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
S = "lab/delegation.py"
MUTATIONS = [
    ("D1", "a handed-on token is no longer cut down to what the next agent and the task need", S, [('        if self.narrow:\n', '        if False:\n')]),
    ("D2", "the limit on hops is ignored", S, [('if self.max_depth is not None and depth > self.max_depth:', 'if False:')]),
    ("D3", "the log stops recording the person and the chain", S, [('        if self.chain_log:\n', '        if False:\n')]),
    ("D4", "a handed-on token no longer checks the one it came from", S, [('if self.cascade and t["parent"] is not None:', 'if False:')]),
    ("D5", "the one-time number and time window are not checked", S, [('        if self.nonce_check:\n', '        if False:\n')]),
    ("D6", "the executor stops checking the gateway's public-key signature", S, [('ok = verify_sig(self.gateway_pub, sig, data)', 'ok = True')]),
    ("D7", "the second signature is no longer required for high-risk actions", S, [('if self.require_cosign and decision.get("action") in self.HIGH_RISK:', 'if False:')]),
    ("D8", "the key's retirement time is ignored", S, [('if k is None or (k["retired"] is not None and self.clock() > k["retired"]):', 'if k is None:')]),
    ("D9", "IDs are no longer prefixed by company", S, [('self.namespace, self.access = namespace, {}', 'self.namespace, self.access = False, {}')]),
    ("D10", "the one-time number and expiry on messages are not checked", S, [('        if self.nonce:\n            if m["nonce"]', '        if False:\n            if m["nonce"]')]),
    ("D11", "the mask goes back to capitals only", S, [('rx = PAN_LOOSE if normalise else PAN_STRICT', 'rx = PAN_STRICT')]),
]
RUN = "import json,sys\nfrom lab import cases_r11\ntry:\n    print(json.dumps(cases_r11.CASES[sys.argv[1]](None)[0]))\nexcept Exception as e:\n    print(json.dumps('error: '+type(e).__name__))\n"


def run_case(src: Path, cid: str) -> str:
    out = subprocess.run([sys.executable, "-c", RUN, cid], cwd=src, capture_output=True, text=True, timeout=120)
    return json.loads(out.stdout.strip().splitlines()[-1])


def main() -> int:
    spec = {c["id"]: c for c in json.loads((ROOT / "cases" / "round-11.json").read_text())["cases"]}
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
    out = ROOT / "results" / "round-11"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{stamp}-mutations.json").write_text(json.dumps(rows, indent=2) + "\n")
    lines = ["# Round eleven: does each case notice when its control is switched off?", "",
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
