from __future__ import annotations
"""Round eight: what happens when an agent goes around the gateway (cases B1 to B12).
The expected results were committed in cases/round-8.json before this file existed.
The AI model behind an agent is not tested: where a case needs an agent that does
the wrong thing, the case makes it do so and checks the wall around it.
Each function takes a detector (not used here) and returns (outcome, details)."""
import copy
import json
import secrets
from datetime import timedelta

from . import cases_r7 as r7
from .actions import API_TOKEN_PATH, EXECUTOR, ApiError, Plumbing
from .bypass import (AGENT_SOURCE, Delegates, ListGate, NetworkDenied, OffenceDesk, bind, reconcile, respond, sponsor_left)
from .lifecycle import BIRTHRIGHT, HrError
from .world import World

CASES = {}
FAR = None   # set per world: a long time from now


def case(cid):
    def wrap(fn):
        CASES[cid] = fn
        return fn
    return wrap


def _new(*agents):
    w = World()
    p = Plumbing(w)
    toks = [p.agent(a, s, set(sc)) for a, s, sc in agents]
    return (w, p, *toks)


def _leak(p, w) -> str:
    """A long-lived token somebody left in a config file. The API accepts it."""
    tok = "idmtok_static_" + secrets.token_hex(10)
    p.api.accept_token(tok, w.clock() + timedelta(days=365))
    return tok


def _direct(p, agent, fn_name, *a, **k):
    src = f"{AGENT_SOURCE}:{agent}"
    return p.net.call(AGENT_SOURCE, "idm-api", lambda: getattr(p.api.as_source(src), fn_name)(*a, **k))


def _legit_disable(p, w, tok, uid, rid):
    p.gateway.submit({"request_id": rid, "action": "disable_user", "target": {"staff_id": uid}, "reason": "leaver"}, tok)
    return p.gateway.approve(rid, w.approver)


@case("B1")
def b1(det):
    w, p, tok = _new(("A-onboarding", "S002", {"idm.user.create", "idm.user.disable"}))
    bind(p, enforce=True)
    p.net.allow(AGENT_SOURCE, "idm-api")
    leak = _leak(p, w)
    try:
        _direct(p, "A-onboarding", "set_active", "S013", False, token=leak)
        refused = False
    except ApiError as e:
        refused = e.status == 401
    still_on = p.api.users["S013"]["active"]
    legit = p.gateway.submit({"request_id": "R-B1-1", "action": "create_user",
                              "target": {"given_name": "Asha", "family_name": "Menon", "email": "asha.menon@kaveri.example", "team": "Support"}}, tok)
    rep = reconcile(p)
    ok = refused and still_on and legit["outcome"] == "executed" and not rep["unmatched"]
    return ("refused_at_api" if ok else "other"), {"direct_call_refused": refused, "account_still_on": still_on, "normal_request": legit["outcome"], "unmatched": len(rep["unmatched"])}


@case("B2")
def b2(det):
    w, p, tok = _new(("A-onboarding", "S002", {"idm.user.create", "idm.user.disable"}))
    bind(p, enforce=False)
    p.net.allow(AGENT_SOURCE, "idm-api")
    leak = _leak(p, w)
    legit = _legit_disable(p, w, tok, "S014", "R-B2-1")
    _direct(p, "A-onboarding", "set_active", "S013", False, token=leak)
    rep = reconcile(p)
    uids = [a["uid"] for a in rep["unmatched"]]
    ok = legit["outcome"] == "executed" and uids == ["S013"] and not p.api.users["S013"]["active"]
    return ("bypass_flagged_exactly_one" if ok else "other"), {"api_changes": rep["changes"], "unmatched_accounts": uids, "legit_outcome": legit["outcome"]}


@case("B3")
def b3(det):
    w, p, tok = _new(("A-onboarding", "S002", {"idm.user.create", "idm.user.disable", "idm.user.read"}))
    bind(p, enforce=False)
    p.net.allow(AGENT_SOURCE, "idm-api")
    leak = _leak(p, w)
    pend = p.gateway.submit({"request_id": "R-B3-1", "action": "disable_user", "target": {"staff_id": "S014"}, "reason": "leaver"}, tok)
    lid, _ = p.vault.lease_api_token(EXECUTOR, "R-B3-lease", "A-onboarding")
    _direct(p, "A-onboarding", "set_active", "S013", False, token=leak)
    res = respond(p, reconcile(p))
    after = p.gateway.submit({"request_id": "R-B3-2", "action": "read_user", "target": {"staff_id": "S013"}}, tok)
    try:
        p.api.get_user("S013", token=leak)
        leak_dead = False
    except ApiError:
        leak_dead = True
    ok = (pend["outcome"] == "pending_approval" and res["killed"] == ["A-onboarding"] and not p.gateway.pending
          and p.vault.leases[lid]["revoked"] and after["outcome"] == "refused" and leak_dead and not p.api.users["S013"]["active"])
    return ("killed_and_revoked_no_auto_rollback" if ok else "other"), {"policy": {k: v for k, v in res.items() if k != "details"},
            "pending_left": len(p.gateway.pending), "lease_revoked": p.vault.leases[lid]["revoked"], "agent_next_request": after["outcome"],
            "leaked_token_dead": leak_dead, "unwanted_change_still_there": not p.api.users["S013"]["active"]}


@case("B4")
def b4(det):
    w, p, tok = _new(("A-onboarding", "S002", {"idm.user.create"}))
    bind(p, enforce=False)          # the API would accept it; only the network stands in the way
    leak = _leak(p, w)
    try:
        _direct(p, "A-onboarding", "set_active", "S013", False, token=leak)
        blocked = False
    except NetworkDenied:
        blocked = True
    logged = bool(w.log.events(kind="network", action="route_denied"))
    legit = p.gateway.submit({"request_id": "R-B4-1", "action": "create_user",
                              "target": {"given_name": "Asha", "family_name": "Menon", "email": "asha.menon@kaveri.example", "team": "Support"}}, tok)
    ok = blocked and logged and all(a['uid'] != 'S013' for a in p.api.audit) and p.api.users["S013"]["active"] and legit["outcome"] == "executed"
    return ("no_route" if ok else "other"), {"call_blocked": blocked, "denied_in_log": logged, "api_changes": len(p.api.audit), "normal_request": legit["outcome"]}


@case("B5")
def b5(det):
    w, p = _new()
    bind(p, enforce=True)
    p.net.allow(AGENT_SOURCE, "idm-api")
    lid, tok = p.vault.lease_api_token(EXECUTOR, "R-B5-1", "A-x")
    try:
        _direct(p, "A-x", "get_user", "S013", token=tok)
        wrong = "accepted"
    except ApiError as e:
        wrong = e.status
    inside = p.api.get_user("S013", token=tok)["id"] == "S013"
    w.clock.advance(minutes=6)
    try:
        p.api.get_user("S013", token=tok)
        late = "accepted"
    except ApiError as e:
        late = e.status
    ok = wrong == 401 and inside and late == 401
    return ("refused_wrong_caller_and_expired" if ok else "other"), {"wrong_caller": wrong, "right_caller_inside_window": inside, "right_caller_after_6_minutes": late}


@case("B6")
def b6(det):
    w, p, tok = _new(("A-lifecycle", "S002", {"idm.user.disable", "idm.user.read"}))
    gate = ListGate(p)
    rid = "R-B6-1"
    gate.submit({"request_id": rid, "action": "disable_user", "target": {"staff_id": "S013"}, "reason": "leaver"}, tok)
    done = p.gateway.approve(rid, w.approver)
    r_active = gate.submit({"request_id": "R-B6-2", "action": "read_user", "target": {"staff_id": "S015"}}, tok)
    alerts_before = len(w.log.events(kind="list", action="watch_alert"))
    r_off = gate.submit({"request_id": "R-B6-3", "action": "read_user", "target": {"staff_id": "S013"}}, tok)
    alerts_after = len(w.log.events(kind="list", action="watch_alert"))
    r_on = gate.submit({"request_id": "R-B6-4", "action": "enable_user", "target": {"staff_id": "S013"}}, tok)
    ok = (done["outcome"] == "executed" and r_active["outcome"] == "executed" and alerts_before == 0 and r_off["outcome"] == "executed"
          and alerts_after == 1 and r_on["outcome"] == "blocked_by_list" and not p.api.users["S013"]["active"])
    return ("watch_alert_reenable_blocked" if ok else "other"), {"read_of_active_account_alerts": alerts_before, "read_of_disabled_account_alerts": alerts_after,
            "reenable": r_on["outcome"], "account_still_off": not p.api.users["S013"]["active"]}


@case("B7")
def b7(det):
    w, p, lc, tok = r7._new(("A-onboarding", "S002", {"idm.user.create"}))
    rid = lc.hr.add_prehire(r7.rec())
    ev = r7.ready(lc, rid)
    uid = r7.onboard(p, lc, tok, ev, "R-B7-1")["user_id"]
    w.clock.advance(days=7)
    lc.sync()
    gate = ListGate(p, lc)
    gate.move(uid, "SUPPORT-AGENT", BIRTHRIGHT["SUPPORT-AGENT"])
    early = gate.request_access(uid, "reports.export", "S002")
    w.clock.advance(days=31)
    flagged = gate.watch_scan()
    not_approver = gate.review_old(uid, "S002")
    rev = gate.review_old(uid, w.approver)
    late = gate.request_access(uid, "reports.export", "S002")
    roles = sorted(lc.roles.get(uid, []))
    ok = (early["outcome"] == "blocked_by_list" and flagged == [uid] and not_approver["outcome"] == "refused" and rev["outcome"] == "reviewed"
          and late["outcome"] == "granted" and "loan.create" not in roles and "reports.export" in roles)
    return ("blocked_flagged_then_granted_after_review" if ok else "other"), {"before_review": early["outcome"], "flagged_after_31_days": flagged,
            "review_by_non_approver": not_approver["outcome"], "after_review": late["outcome"], "roles_now": roles}


@case("B8")
def b8(det):
    w, p, tok = _new(("A-onboarding", "S002", {"idm.user.disable", "idm.user.read"}))
    pend = p.gateway.submit({"request_id": "R-B8-1", "action": "disable_user", "target": {"staff_id": "S014"}, "reason": "leaver"}, tok)
    lid, _ = p.vault.lease_api_token(EXECUTOR, "R-B8-lease", "A-onboarding")
    out = sponsor_left(p, "S002")
    nxt = p.gateway.submit({"request_id": "R-B8-2", "action": "read_user", "target": {"staff_id": "S013"}}, tok)
    appr = p.gateway.approve("R-B8-1", w.approver)
    ok = (pend["outcome"] == "pending_approval" and out["disabled"] == ["A-onboarding"] and out["cancelled"] == 1 and p.vault.leases[lid]["revoked"]
          and nxt["outcome"] == "refused" and appr["outcome"] == "refused" and p.api.users["S014"]["active"])
    return ("agent_off_pending_cancelled_leases_revoked" if ok else "other"), {"switched_off": out["disabled"], "waiting_requests_cancelled": out["cancelled"],
            "lease_revoked": p.vault.leases[lid]["revoked"], "next_request": nxt["outcome"], "late_approval": appr["outcome"]}


@case("B9")
def b9(det):
    w, p, tok = _new(("A-onboarding", "S002", {"idm.user.create"}))
    d = Delegates(p)
    d.register("S008", "H-helper-1", "HR-BU-1", "screen_reader_ui")
    try:
        d.register("S008", "H-helper-3", "A-onboarding", "delegate")
        agent_ok = True
    except HrError:
        agent_ok = False
    try:
        d.register("S008", "H-helper-4", "HR-BU-1", "blind from birth")
        free_text = True
    except HrError:
        free_text = False
    rec = d.act("H-helper-1", "S008")
    unrec = d.act("H-helper-2", "S008")
    blob = json.dumps(w.log.lines, default=str).lower()
    clean = "blind" not in blob and "visual" not in blob
    alerts = w.log.events(kind="delegate", action="watch_alert")
    ok = (not agent_ok and not free_text and rec == "delegate" and unrec == "watch" and len(alerts) == 1 and clean)
    return ("recorded_helper_not_flagged" if ok else "other"), {"recorded_helper": rec, "unrecorded_helper": unrec, "agent_could_register": agent_ok,
            "free_text_accepted": free_text, "medical_words_in_log": not clean}


@case("B10")
def b10(det):
    w, p, tok = _new(("A-onboarding", "S002", {"idm.user.read"}))
    activity = ([{"who": "S013", "kind": "export", "day": "2026-10-20", "rows": 300}]
                + [{"who": "S013", "kind": "export", "day": f"2026-10-{d}", "rows": 12000} for d in (27, 28, 29, 30)]
                + [{"who": "S014", "kind": "export", "day": d, "rows": 400} for d in ("2026-10-27", "2026-10-28")])
    desk = OffenceDesk(p)
    sigs = desk.scan(activity, {"S013": "2026-10-26", "S014": "2026-10-26"})
    case_ = desk.open_case(sigs[0], owner="S031", copied_by="S006")
    intact = desk.verify(case_)
    forged = copy.deepcopy(case_)
    forged["evidence"][0]["rows"] = 1
    tamper_seen = not desk.verify(forged)
    no_verdict = not ({"verdict", "offence", "guilty", "accused"} & set(case_))
    police = p.gateway.submit({"request_id": "R-B10-1", "action": "report_to_police", "target": {"staff_id": "S013"}}, tok)
    ok = (len(sigs) == 1 and sigs[0]["who"] == "S013" and sigs[0]["count"] == 4 and intact and tamper_seen and no_verdict
          and case_["status"] == "for_review" and case_["custody"] and police["outcome"] in ("rejected", "blocked"))
    return ("signal_to_person_with_evidence" if ok else "other"), {"signals": [(s["who"], s["count"]) for s in sigs], "owner": case_["owner"],
            "custody": case_["custody"], "evidence_hash_checks": intact, "edited_copy_detected": tamper_seen, "agent_asked_to_report": police["outcome"]}


@case("B11")
def b11(det):
    w, p, lc, tok = r7._new(("A-onboarding", "S002", {"idm.user.create", "idm.user.read"}))
    rid = lc.hr.add_prehire(r7.rec(disability_note="uses a screen reader"))
    ev = r7.ready(lc, rid)
    made = r7.onboard(p, lc, tok, ev, "R-B11-1")
    uid = made["user_id"]
    ask_pan = p.gateway.submit({"request_id": "R-B11-2", "action": "read_user", "target": {"staff_id": uid}, "fields": ["pan"]}, tok)
    t = r7.create_req(ev, "R-B11-3")
    t["target"] = {**t["target"], "medical_note": "uses a screen reader"}
    ask_med = p.gateway.submit(t, tok)
    read = p.gateway.submit({"request_id": "R-B11-4", "action": "read_user", "target": {"staff_id": uid}}, tok)
    blob = json.dumps(p.gateway.agent_view, default=str) + json.dumps(w.log.lines, default=str)
    secrets_seen = [name for name, val in (("PAN", r7.PAN), ("Aadhaar", r7.AADHAAR), ("bank", r7.BANK), ("medical note", "screen reader")) if val in blob]
    ok = (made["outcome"] == "executed" and ask_pan["outcome"] == "rejected" and ask_med["outcome"] == "rejected" and read["outcome"] == "executed"
          and set(read["user"]) == {"id", "team", "active"} and not secrets_seen)
    return ("refused_sensitive_none_leaked" if ok else "other"), {"ask_for_pan": ask_pan["outcome"], "ask_with_medical_note": ask_med["outcome"],
            "fields_in_read_reply": sorted(read.get("user", {})), "sensitive_values_found": secrets_seen}


@case("B12")
def b12(det):
    w, p, tok = _new(("A-onboarding", "S002", {"idm.user.create", "idm.user.disable"}))
    p.gateway.submit({"request_id": "R-B12-1", "action": "create_user",
                      "target": {"given_name": "Asha", "family_name": "Menon", "email": "asha.menon@kaveri.example", "team": "Support"}}, tok)
    _legit_disable(p, w, tok, "S014", "R-B12-2")
    intact, _ = w.log.verify()
    anchor = w.log.anchor()
    edited = copy.deepcopy(w.log)
    edited.lines[4]["body"]["action"] = "approved_by_nobody"
    ok_edit, where = edited.verify()
    cut = copy.deepcopy(w.log)
    del cut.lines[-3:]
    ok_cut, why_cut = cut.verify_against(anchor)
    ok_full, _ = w.log.verify_against(anchor)
    ok = intact and not ok_edit and where == 5 and not ok_cut and ok_full
    return ("tamper_detected" if ok else "other"), {"untouched_log_passes": intact and ok_full, "edit_breaks_chain_at_line": where, "cut_noticed": not ok_cut, "cut_message": why_cut}
