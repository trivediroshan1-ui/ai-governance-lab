#!/usr/bin/env python3
"""Round eight check on the tests themselves: switch one control off at a time in a
copy of the code (each run in its own process) and see whether the matching case
stops passing. Run: python3 mutations_r8.py"""
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
B, A, H = "lab/bypass.py", "lab/actions.py", "lab/hashlog.py"
MUTATIONS = [
    ("B1", "the API does not check who is calling", B, [('if self.enforce and self.source not in self.allowed:', 'if False:')]),
    ("B2", "reconciliation does not report unmatched changes", B, [('unmatched.append(a)', 'pass')]),
    ("B3", "the policy does not switch off the agent it can trace", B, [('if a["source"].startswith(AGENT_SOURCE + ":"):', 'if False:')]),
    ("B3", "the policy does not revoke the leaked token", B, [('out["leaked_tokens_revoked"] += p.api.revoke_by_id(a["token_id"])', 'pass')]),
    ("B4", "the network allows every route", B, [('if (src, dst) not in self.routes:', 'if False:')]),
    ("B5", "the API does not check when a credential expires", A, [('t is None or t["revoked"] or t["expires"] <= self.clock()', 't is None or t["revoked"]')]),
    ("B6", "no watch alert for touching a disabled account", B, [('if state == "disabled" and action in WATCH_ACTIONS:', 'if False:')]),
    ("B6", "switching an account back on is not blocked", B, [('if action in BLOCK_ACTIONS:', 'if False:')]),
    ("B7", "new access is allowed before the old access is reviewed", B, [('if rec and not rec["reviewed"]:', 'if False:')]),
    ("B7", "a mover who keeps old access is not flagged", B, [('if not rec["reviewed"] and now - rec["since"] >= timedelta(days=MOVER_DAYS):', 'if False:')]),
    ("B7", "the review does not remove the old access", B, [('self.lc.roles[uid] = set(rec["new_birthright"])', 'pass')]),
    ("B8", "leaving sponsor: lent credentials are not revoked", B, [('out["leases_revoked"] += p.vault.revoke_for_agent(agent)', 'pass')]),
    ("B8", "leaving sponsor: waiting requests are not cancelled", B, [('out["cancelled"] += p.gateway.on_kill(agent)["cancelled"]', 'pass')]),
    ("B9", "anyone can record a helper, including an agent", B, [('if not HR_ROLES.get(approved_by):', 'if False:')]),
    ("B9", "free text is accepted for an accommodation", B, [('if code not in ACCOMMODATION_CODES:', 'if False:')]),
    ("B9", "an unrecorded helper is treated as recorded", B, [('if (helper, employee) in self.pairs:', 'if True:')]),
    ("B10", "the evidence hash is not checked", B, [('return self._hash(case["evidence"]) == case["evidence_sha256"]', 'return True')]),
    ("B10", "the rule fires on a single export", B, [('if len(mine) >= big:', 'if len(mine) >= 1:')]),
    ("B11", "the request shape allows an extra fields entry", A, [('OPTIONAL = {"reason", "hire_event"}', 'OPTIONAL = {"reason", "hire_event", "fields"}')]),
    ("B12", "the chain check ignores edited lines", H, [('if line["prev"] != prev or line["hash"] != _digest(prev, line["body"]):', 'if line["prev"] != prev:')]),
    ("B12", "the anchor check ignores cut-off lines", H, [('if not self.lines or self.lines[-1]["body"]["seq"] < anchor["last_seq"]:', 'if False:'),
                                                       ('if not match or match[0]["hash"] != anchor["head"]:', 'if False:')]),
]
RUN = "import json,sys\nfrom lab import cases_r8\ntry:\n    print(json.dumps(cases_r8.CASES[sys.argv[1]](None)[0]))\nexcept Exception as e:\n    print(json.dumps('error: '+type(e).__name__))\n"


def run_case(src: Path, cid: str) -> str:
    out = subprocess.run([sys.executable, "-c", RUN, cid], cwd=src, capture_output=True, text=True, timeout=120)
    return json.loads(out.stdout.strip().splitlines()[-1])


def main() -> int:
    spec = {c["id"]: c for c in json.loads((ROOT / "cases" / "round-8.json").read_text())["cases"]}
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
                     "case_notices": normal == spec[cid]["expected"] and after != spec[cid]["expected"] and not str(after).startswith("error")})
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = ROOT / "results" / "round-8"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{stamp}-mutations.json").write_text(json.dumps(rows, indent=2) + "\n")
    lines = ["# Round eight: does each case notice when its control is switched off?", "",
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
