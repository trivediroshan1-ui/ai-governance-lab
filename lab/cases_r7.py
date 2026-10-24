from __future__ import annotations
"""Round seven: the HR side of identity onboarding (cases H1 to H12). The expected
results were committed in cases/round-7.json before this file existed. The AI
model behind an agent is not tested: where a case needs an agent that proposes
something it should not, the case makes it do so and checks the wall around it.
Each function takes a detector (not used here) and returns (outcome, details)."""
import json
import random

from . import ids
from .actions import API_TOKEN_PATH, Plumbing
from .lifecycle import BIRTHRIGHT, EVENT_FIELDS, HrError, Lifecycle, _h
from .world import World

CASES = {}


def case(cid):
    def wrap(fn):
        CASES[cid] = fn
        return fn
    return wrap


def _new(*agents):
    w = World()
    p = Plumbing(w)
    toks = [p.agent(a, s, set(sc)) for a, s, sc in agents]
    lc = Lifecycle(p)
    return (w, p, lc, *toks)


_RNG = random.Random(7)
PAN, AADHAAR = ids.make_pan(_RNG), ids.make_aadhaar(_RNG)
BANK = "".join(str(_RNG.randint(0, 9)) for _ in range(12))


def rec(**kw):
    base = dict(kind="employee", given_name="Asha", family_name="Menon", email="asha.menon@kaveri.example", team="Support",
                job_code="LOAN-OFFICER", manager="S002", start_date="2026-11-09", pan=PAN, aadhaar=AADHAAR, bank=BANK)
    base.update(kw)
    return base


def vendor(**kw):
    base = dict(kind="vendor", given_name="Vikram", family_name="Nair", email="vikram.nair@vendor.example", team="Vendor",
                job_code="VENDOR-TESTER", manager="S002", start_date="2026-11-02", sponsor="S002", end_date="2027-01-31", tprm_ok=True)
    base.update(kw)
    return base


def ready(lc, rid):
    lc.hr.set_bgv(rid, "clear")
    lc.hr.approve(rid, "HR-TA-1", "ta_hr")
    lc.hr.approve(rid, "HR-BU-1", "bu_hr")
    return lc.hr.hire_event(rid)


def create_req(ev, request_id):
    return {"request_id": request_id, "action": "create_user", "target": {k: ev[k] for k in EVENT_FIELDS},
            "hire_event": ev["event_id"], "reason": "Joiner per hire event"}


def onboard(p, lc, tok, ev, name):
    return p.gateway.submit(create_req(ev, name), tok)


@case("H1")
def h1(det):
    w, p, lc, tok = _new(("A-onboarding", "S002", {"idm.user.create"}))
    rid = lc.hr.add_prehire(rec())
    ev = ready(lc, rid)
    r = onboard(p, lc, tok, ev, "R-H1-1")
    uid = r.get("user_id")
    lc.sync()
    before = p.api.users[uid]["active"]
    w.clock.advance(days=7)
    lc.sync()
    after = p.api.users[uid]["active"]
    roles = sorted(lc.roles.get(uid, []))
    ok = r["outcome"] == "executed" and not before and after and set(roles) == BIRTHRIGHT["LOAN-OFFICER"]
    return ("created_from_hr_event" if ok else "other"), {"reply": r, "active_before_start_date": before, "active_on_start_date": after, "roles": roles}


@case("H2")
def h2(det):
    w, p, lc, tok = _new(("A-onboarding", "S002", {"idm.user.create"}))
    target = {k: rec()[k] for k in EVENT_FIELDS}
    a = p.gateway.submit({"request_id": "R-H2-1", "action": "create_user", "target": target}, tok)
    b = p.gateway.submit({"request_id": "R-H2-2", "action": "create_user", "target": target, "hire_event": "HE-9999"}, tok)
    ok = a["outcome"] == "refused" and b["outcome"] == "refused" and len(p.api.users) == 40
    return ("refused_no_hr_event" if ok else "other"), {"no_event": a, "made_up_event": b, "accounts_after": len(p.api.users)}


@case("H3")
def h3(det):
    w, p, lc = _new()
    rid = lc.hr.add_prehire(rec())
    lc.hr.approve(rid, "HR-TA-1", "ta_hr")
    lc.hr.approve(rid, "HR-BU-1", "bu_hr")
    pending = lc.hr.hire_event(rid)
    why = lc.hr.why_not(rid)
    lc.hr.set_bgv(rid, "clear")
    cleared = lc.hr.hire_event(rid)
    ok = pending is None and cleared is not None
    return ("held_until_cleared" if ok else "other"), {"while_pending": why, "event_after_clear": cleared and cleared["event_id"]}


@case("H4")
def h4(det):
    w, p, lc = _new()
    rid = lc.hr.add_prehire(rec())
    lc.hr.set_bgv(rid, "clear")
    lc.hr.approve(rid, "HR-DUAL-1", "ta_hr")
    one = lc.hr.hire_event(rid)
    try:
        lc.hr.approve(rid, "HR-DUAL-1", "bu_hr")
        same = "accepted"
    except HrError:
        same = "refused"
    still = lc.hr.hire_event(rid)
    lc.hr.approve(rid, "HR-BU-1", "bu_hr")
    done = lc.hr.hire_event(rid)
    ok = one is None and same == "refused" and still is None and done is not None
    return ("held_until_two_people_approve" if ok else "other"), {"after_one_approval": one, "same_person_second_role": same, "after_two_people": done and done["event_id"]}


@case("H5")
def h5(det):
    w, p, lc, tok = _new(("A-onboarding", "S002", {"idm.user.create"}))
    rid = lc.hr.add_prehire(rec())
    ev = ready(lc, rid)
    r = onboard(p, lc, tok, ev, "R-H5-1")
    lc.sync()
    w.clock.advance(days=7)
    lc.sync()
    blob = json.dumps(ev) + json.dumps(p.api.users) + json.dumps(w.log.lines, default=str) + json.dumps(p.gateway.agent_view, default=str)
    grouped = f"{AADHAAR[0:4]} {AADHAAR[4:8]} {AADHAAR[8:12]}"
    found = [name for name, v in (("PAN", PAN), ("Aadhaar", AADHAAR), ("Aadhaar", grouped), ("bank account", BANK)) if v in blob]
    hr_holds = all(lc.hr.records[rid].get(k) for k in ("pan", "aadhaar", "bank"))
    ok = r["outcome"] == "executed" and not found and hr_holds
    return ("minimum_only" if ok else "other"), {"fields_in_event": sorted(ev), "found_outside_hr": found, "hr_record_still_holds_them": hr_holds}


@case("H6")
def h6(det):
    w, p, lc, tok = _new(("A-onboarding", "S002", {"idm.user.create"}))
    base = {"crm.read", "loan.create", "reports.export"}
    lc.peers["LOAN-OFFICER"] = [base | {"loan.view", "loan.approve"}] * 3 + [base] * 2
    rid = lc.hr.add_prehire(rec())
    ev = ready(lc, rid)
    uid = onboard(p, lc, tok, ev, "R-H6-1")["user_id"]
    w.clock.advance(days=7)
    lc.sync()
    before = set(lc.roles[uid])
    proposals = lc.propose_extras(uid, "LOAN-OFFICER")
    unchanged = set(lc.roles[uid]) == before
    export = lc.request_extra(uid, "reports.export", "S002")
    approve = lc.request_extra(uid, "loan.approve", "S002")
    other = lc.request_extra(uid, "admin.all", "S002")
    ok = unchanged and export["outcome"] == "granted" and approve["outcome"] == "refused" and other["outcome"] == "refused" and "loan.approve" in proposals
    return ("proposals_only" if ok else "other"), {"proposed_from_peers": proposals, "roles_changed_by_proposing": not unchanged, "reports.export": export,
                                                 "loan.approve": approve, "admin.all": other, "final_roles": sorted(lc.roles[uid])}


@case("H7")
def h7(det):
    w, p, lc, tok = _new(("A-onboarding", "S002", {"idm.user.create"}))
    rid = lc.hr.add_prehire(rec())
    ev = ready(lc, rid)
    uid = onboard(p, lc, tok, ev, "R-H7-1")["user_id"]
    lc.sync()
    lc.hr.cancel(rid)
    lc.sync()
    w.clock.advance(days=8)
    lc.sync()
    again = p.gateway.submit(create_req(ev, "R-H7-2"), tok)
    ok = not p.api.users[uid]["active"] and uid not in lc.activated and again["outcome"] == "refused"
    return ("disabled_before_start" if ok else "other"), {"active_after_start_date_passed": p.api.users[uid]["active"], "ever_switched_on": uid in lc.activated,
                                                         "new_request_using_withdrawn_event": again["outcome"]}


@case("H8")
def h8(det):
    w, p, lc, tok = _new(("A-onboarding", "S002", {"idm.user.create"}))
    uids = []
    for i, email in enumerate(("asha.menon@kaveri.example", "ravi.shah@kaveri.example")):
        rid = lc.hr.add_prehire(rec(email=email, given_name="Asha" if i == 0 else "Ravi", family_name="Menon" if i == 0 else "Shah", pan=None))
        ev = ready(lc, rid)
        uids.append(onboard(p, lc, tok, ev, f"R-H8-{i}")["user_id"])
    w.clock.advance(days=7)
    lc.sync()
    a, b = uids
    lc.enrol_mfa(a)                      # first person: MFA only
    lc.sign_policy(b)                    # second person: policy only
    only_mfa = lc.open_sensitive_app(a)
    only_policy = lc.open_sensitive_app(b)
    lc.sign_policy(a)
    lc.enrol_mfa(b)
    both = (lc.open_sensitive_app(a), lc.open_sensitive_app(b))
    ok = (not only_mfa[0]) and (not only_policy[0]) and all(x[0] for x in both)
    return ("refused_until_mfa_and_policy" if ok else "other"), {"mfa_but_no_policy": only_mfa[1], "policy_but_no_mfa": only_policy[1], "both_done": [x[1] for x in both]}


@case("H9")
def h9(det):
    w, p, lc, tok = _new(("A-onboarding", "S002", {"idm.user.create"}))
    gaps = {}
    for name, kw in (("no sponsor", {"sponsor": None, "email": "v1@vendor.example"}), ("no end date", {"end_date": None, "email": "v2@vendor.example"}),
                     ("no security review", {"tprm_ok": False, "email": "v3@vendor.example"})):
        rid = lc.hr.add_prehire(vendor(**kw))
        lc.hr.approve(rid, "HR-BU-1", "bu_hr")
        gaps[name] = lc.hr.why_not(rid)
    rid = lc.hr.add_prehire(vendor())
    lc.hr.approve(rid, "HR-BU-1", "bu_hr")
    ev = lc.hr.hire_event(rid)
    r = onboard(p, lc, tok, ev, "R-H9-1") if ev else {"outcome": "no event"}
    lc.sync()
    uid = r.get("user_id")
    ok = all(gaps.values()) and ev is not None and ev.get("end_date") == "2027-01-31" and r["outcome"] == "executed" and p.api.users[uid]["active"]
    return ("refused_until_complete" if ok else "other"), {"each_gap": gaps, "complete_record_event": ev and ev["event_id"], "expiry_on_event": ev and ev.get("end_date")}


@case("H10")
def h10(det):
    w, p, lc, tok = _new(("A-onboarding", "S002", {"idm.user.create"}))
    rid = lc.hr.add_prehire(vendor())
    lc.hr.approve(rid, "HR-BU-1", "bu_hr")
    ev = lc.hr.hire_event(rid)
    uid = onboard(p, lc, tok, ev, "R-H10-1")["user_id"]
    lc.sync()
    active_before = p.api.users[uid]["active"]
    w.clock.advance(days=100)
    out = lc.sync()
    ok = active_before and not p.api.users[uid]["active"] and out["expired"] == [uid]
    return ("expired_and_disabled" if ok else "other"), {"active_before_end_date": active_before, "after_end_date": p.api.users[uid]["active"], "job_output": out}


@case("H11")
def h11(det):
    w, p, lc, tok = _new(("A-onboarding", "S002", {"idm.user.create"}))
    rid = lc.hr.add_prehire(rec())
    ev = ready(lc, rid)
    good = onboard(p, lc, tok, ev, "R-H11-1")["user_id"]
    lid, t = p.vault.lease_api_token("it-admin", "direct", "it-admin")
    bad = p.api.create_user({"given_name": "Temp", "family_name": "Admin", "email": "temp.admin@kaveri.example", "team": "IT"}, token=t)["id"]
    p.vault.revoke_lease(lid)
    rep = lc.reconcile()
    ok = rep["orphans"] == [bad] and good not in rep["orphans"]
    return ("flagged_orphan" if ok else "other"), {"report": rep, "event_account": good, "direct_account": bad}


@case("H12")
def h12(det):
    w, p, lc = _new()
    lc.hr.known_pan_hashes[_h(PAN)] = "S004"          # an existing employee already has this PAN
    rid = lc.hr.add_prehire(rec())
    lc.hr.set_bgv(rid, "clear")
    lc.hr.approve(rid, "HR-TA-1", "ta_hr")
    lc.hr.approve(rid, "HR-BU-1", "bu_hr")
    held = lc.hr.hire_event(rid)
    why = lc.hr.why_not(rid)
    lc.hr.clear_hold(rid, "HR-BU-2")
    after = lc.hr.hire_event(rid)
    ok = held is None and after is not None
    return ("held_duplicate" if ok else "other"), {"before_review": why, "event_after_review": after and after["event_id"]}
