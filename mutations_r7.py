#!/usr/bin/env python3
"""Round seven check on the tests themselves: switch one control off at a time in a
copy of lab/lifecycle.py and see whether the matching case stops passing.
Run: python3 mutations_r7.py"""
import importlib
import json
import sys
import types
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
SRC = (ROOT / "lab" / "lifecycle.py").read_text()

MUTATIONS = [
    ("H1", "an account is not switched off before its start date", 'if ev["start_date"] > today:', "if False:"),
    ("H2", "the gateway accepts a create request with no approved hire event", 'return False, "no approved HR hire event backs this request"', 'return True, ""'),
    ("H3", "background verification is not required", 'if r["bgv"] != "clear":', "if False:"),
    ("H4", "one HR approval is enough", 'if set(r["approvals"]) != {"ta_hr", "bu_hr"}:', 'if not r["approvals"]:'),
    ("H4", "the same person may give both approvals", "if who in r[\"approvals\"].values():", "if False:"),
    ("H5", "the hire event carries the PAN", '"event_id": eid, "record": rid,', '"event_id": eid, "record": rid, "pan": r.get("pan"),'),
    ("H6", "toxic combinations are not checked on extra access", "if (a <= have and b <= {role}) or (b <= have and a <= {role}):", "if False:"),
    ("H7", "a withdrawn offer does not disable the account", 'if rec["cancelled"]:', "if False:"),
    ("H8", "MFA enrolment is not required", "if uid not in self.mfa:", "if False:"),
    ("H8", "the signed policy is not required", "if uid not in self.policy_signed:", "if False:"),
    ("H9", "a vendor worker needs no sponsor", 'if not r.get("sponsor"):', "if False:"),
    ("H10", "vendor accounts do not expire on their end date", 'if ev["kind"] == "vendor" and ev["end_date"] <= today:', "if False:"),
    ("H11", "reconciliation ignores accounts with no HR record", 'and u["userName"] not in emails)', "and False)"),
    ("H12", "a duplicate PAN is not held", "if h in self.known_pan_hashes or others:", "if False:"),
]


def load(src: str):
    mod = types.ModuleType("lab.lifecycle")
    mod.__package__ = "lab"
    mod.__file__ = str(ROOT / "lab" / "lifecycle.py")
    sys.modules["lab.lifecycle"] = mod
    exec(compile(src, mod.__file__, "exec"), mod.__dict__)
    import lab.cases_r7 as c
    importlib.reload(c)
    return c


def main() -> int:
    spec = {c["id"]: c for c in json.loads((ROOT / "cases" / "round-7.json").read_text())["cases"]}
    base = load(SRC)
    rows = []
    for cid, what, old, new in MUTATIONS:
        assert SRC.count(old) == 1, f"text for {cid} ({what}) not found exactly once"
        normal = base.CASES[cid](None)[0]
        c = load(SRC.replace(old, new))
        try:
            after = c.CASES[cid](None)[0]
        except Exception as e:
            after = f"error: {type(e).__name__}"
        rows.append({"case": cid, "switched_off": what, "expected": spec[cid]["expected"], "normal": normal, "with_control_off": after,
                     "case_notices": normal == spec[cid]["expected"] and after != spec[cid]["expected"] and not str(after).startswith("error")})
    load(SRC)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = ROOT / "results" / "round-7"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{stamp}-mutations.json").write_text(json.dumps(rows, indent=2) + "\n")
    lines = ["# Round seven: does each case notice when its control is switched off?", "",
             f"Run {stamp} UTC. One control at a time is removed from a copy of lab/lifecycle.py.", "",
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
