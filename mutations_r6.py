#!/usr/bin/env python3
"""Round six check on the tests themselves: switch one control off at a time in
a copy of lab/actions.py and see whether the matching case stops passing.
If a case still passes with its control removed, the case proves nothing.
Run: python3 mutations_r6.py"""
import importlib
import json
import sys
import types
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
SRC = (ROOT / "lab" / "actions.py").read_text()

# case, what is switched off, exact text to change, replacement
MUTATIONS = [
    ("T2", "the executor writes the credential into the log",
     'lease=prepared["lease"], **logged)', 'lease=prepared["lease"], token=tok, **logged)'),
    ("T4", "disable_user no longer needs an approval",
     '"disable_user": {"scope": "idm.user.disable", "approval": True,', '"disable_user": {"scope": "idm.user.disable", "approval": False,'),
    ("T5", "the agent's own sponsor may approve",
     "if approver == agent.sponsor:", "if False:"),
    ("T7", "the shape check lets unknown fields through",
     "extra = set(req) - REQUIRED - OPTIONAL", "extra = set()"),
    ("T8", "the vault lets the agent read the credential",
     "self.vault.allow(EXECUTOR, API_TOKEN_PATH, API_PASSWORD_PATH)       # only the executor can read",
     "self.vault.allow(EXECUTOR, API_TOKEN_PATH, API_PASSWORD_PATH); self.vault.allow('A-onboarding', API_TOKEN_PATH, API_PASSWORD_PATH)"),
    ("T9", "the kill switch does not revoke credential leases",
     'c["leases_revoked"] = self.vault.revoke_for_agent(agent_id)', 'c["leases_revoked"] = 0'),
    ("T10", "the executor does not remember request ids",
     'if decision["request_id"] in self.done:', "if False:"),
    ("T11", "the gateway writes the reason text into the log",
     "reason_hash=_short_hash(reason_text), reason_length=len(reason_text))",
     "reason_hash=_short_hash(reason_text), reason_length=len(reason_text), reason_text=reason_text)"),
    ("T12", "no rate limit",
     'if len(recent) >= spec["limit"]:', "if False:"),
    ("T13", "the action's scope is not checked",
     'if spec["scope"] not in claims["scp"]:', "if False:"),
    ("T14", "the executor does not check the gateway's signature",
     'if not isinstance(decision.get("sig"), str) or not hmac.compare_digest(decision["sig"], good):', "if False:"),
    ("T16", "the API accepts credentials past their expiry",
     'if t is None or t["revoked"] or t["expires"] <= self.clock():', 'if t is None or t["revoked"]:'),
]


def load(src: str):
    mod = types.ModuleType("lab.actions")
    mod.__package__ = "lab"
    mod.__file__ = str(ROOT / "lab" / "actions.py")
    sys.modules["lab.actions"] = mod
    exec(compile(src, mod.__file__, "exec"), mod.__dict__)
    import lab.cases_r6 as c
    importlib.reload(c)
    return c


def main() -> int:
    spec = {c["id"]: c for c in json.loads((ROOT / "cases" / "round-6.json").read_text())["cases"]}
    base = load(SRC)
    rows = []
    for cid, what, old, new in MUTATIONS:
        assert SRC.count(old) == 1, f"text for {cid} not found exactly once"
        before = base.CASES[cid](None)[0]
        c = load(SRC.replace(old, new))
        try:
            after = c.CASES[cid](None)[0]
        except Exception as e:      # a crash also means the control mattered
            after = f"error: {type(e).__name__}"
        rows.append({"case": cid, "switched_off": what, "expected": spec[cid]["expected"], "normal": before, "with_control_off": after,
                     "case_notices": before == spec[cid]["expected"] and after != spec[cid]["expected"] and not str(after).startswith("error")})
    load(SRC)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = ROOT / "results" / "round-6"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{stamp}-mutations.json").write_text(json.dumps(rows, indent=2) + "\n")
    lines = ["# Round six: does each case notice when its control is switched off?", "",
             f"Run {stamp} UTC. One control at a time is removed from a copy of lab/actions.py.", "",
             "| Case | Control switched off | Normal result | Result with control off | Case notices |", "|---|---|---|---|---|"]
    lines += [f"| {r['case']} | {r['switched_off']} | {r['normal']} | {r['with_control_off']} | {'yes' if r['case_notices'] else 'NO'} |" for r in rows]
    (out / f"{stamp}-mutations.md").write_text("\n".join(lines) + "\n")
    noticed = sum(r["case_notices"] for r in rows)
    print(f"{noticed} of {len(rows)} cases notice when their control is switched off")
    for r in rows:
        if not r["case_notices"]:
            print("  does not notice:", r["case"], r["switched_off"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
