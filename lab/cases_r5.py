from __future__ import annotations
"""Round five: gaps I found in my own audit on 24 Oct 2026. Vendor and third-party
AI access (V), retrieval that ignores document permissions (R), and more
identity and audit cases (I13 to I18, E15, E16). The expected results were
committed in cases/round-5.json before this file existed. Each function takes
a detector (not used here) and returns (outcome, details)."""
import json
from datetime import timedelta

from .cases import ask
from .consent import Consents
from .identity import IdentityError
from .retrieval import Search
from .world import World

CASES = {}


def case(cid):
    def wrap(fn):
        CASES[cid] = fn
        return fn
    return wrap


def _people(w):
    w.identity.people_scopes = {"S003": {"crm.read", "email.draft"}, "S008": {"crm.read"}}


# Track V: vendor and third-party AI access

@case("V1")
def v1(det):
    w = World()
    c = Consents(w.staff, w.log, w.clock)
    r = c.request("InboxPilot AI (made up)", "Vendor X (made up)", ["mail.read.all", "files.read.all"])
    return r["outcome"], {"reason": r["reason"], "grants_on_file": len(c.grants)}


@case("V2")
def v2(det):
    w = World()
    c = Consents(w.staff, w.log, w.clock)
    r = c.request("FAQ Helper AI (made up)", "Vendor X (made up)", ["files.read:/Shared/Support FAQ"], data_owner="S002")
    before = c.use("FAQ Helper AI (made up)", "files.read:/Shared/Support FAQ")
    other = c.use("FAQ Helper AI (made up)", "files.read:/HR/Salary review")
    w.clock.advance(days=91)
    after = c.use("FAQ Helper AI (made up)", "files.read:/Shared/Support FAQ")
    ok = r["outcome"] == "granted" and before and not other and not after
    return ("granted_with_expiry" if ok else "other"), {"granted": r, "works_on_day_0": before,
                                                       "reads_a_folder_not_granted": other, "works_on_day_91": after}


@case("V3")
def v3(det):
    w = World()
    c = Consents(w.staff, w.log, w.clock)
    s = "files.read:/Shared/Support FAQ"
    c.request("Used App (made up)", "Vendor X (made up)", [s], data_owner="S002")
    c.request("Idle App (made up)", "Vendor Y (made up)", [s], data_owner="S002")
    w.clock.advance(days=10)
    c.use("Used App (made up)", s)
    w.clock.advance(days=30)
    day40 = c.review()
    w.clock.advance(days=60)
    day100 = c.review()
    still = c.use("Used App (made up)", s)
    ok = day40["unused"] == ["Idle App (made up)"] and len(day100["expired"]) == 2 and not still
    return ("expired_and_flagged" if ok else "other"), {"review_day_40": day40, "review_day_100": day100,
                                                       "used_app_works_after_expiry": still}


@case("V4")
def v4(det):
    w = World()
    c = Consents(w.staff, w.log, w.clock)
    s = ["files.read:/Customers/Loan files"]
    abroad = c.request("LoanReader AI (made up)", "Vendor Z (made up)", s, region="US", data_owner="S002")
    home = c.request("LoanReader AI (made up)", "Vendor Z (made up)", s, region="IN", data_owner="S002")
    return abroad["outcome"], {"processing_abroad": abroad, "same_app_processing_in_india": home}


# Track R: retrieval

@case("R1")
def r1(det):
    w = World()
    s = Search(w.staff)
    user = "S008"   # support team
    plain = s.search("salary review", user, "plain")
    live = s.search("salary review", user, "live")
    leaked = sorted(set(plain) - set(live))
    return ("leaks" if "D2" in plain and "D2" not in live else "no_leak"), {
        "user_team": w.staff[7]["team"], "plain_search_returns": plain, "permission_checked_returns": live,
        "files_the_person_cannot_open_but_plain_search_returned": leaked}


@case("R2")
def r2(det):
    w = World()
    s = Search(w.staff)
    user = "S004"   # HR
    before = s.search("salary", user, "index")
    s.move(user, "Support")
    stale = s.search("salary", user, "index")
    live = s.search("salary", user, "live")
    s.refresh_index()
    refreshed = s.search("salary", user, "index")
    ok = before == ["D2"] and stale == ["D2"] and live == [] and refreshed == []
    return ("leaks_until_refresh" if ok else "other"), {
        "in_HR": before, "after_move_stale_index": stale, "after_move_live_check": live, "after_index_refresh": refreshed}


# Track I: more agent identity

@case("I13")
def i13(det):
    w = World()
    _people(w)
    w.identity.register_agent("agent-collect", "S003", {"crm.read"})
    old = w.identity.issue_token("agent-collect")
    w.identity.verify(old, "crm.read")
    held = w.identity.sponsor_moved("S003", "Risk")

    def fails(fn):
        try:
            fn()
            return False
        except IdentityError:
            return True
    old_dead = fails(lambda: w.identity.verify(old, "crm.read"))
    no_new = fails(lambda: w.identity.issue_token("agent-collect"))
    self_confirm = fails(lambda: w.identity.recertify_agent("agent-collect", "S003"))
    w.clock.advance(minutes=5)             # time passes before the new approver confirms it
    w.identity.recertify_agent("agent-collect", "S001")
    new = w.identity.issue_token("agent-collect")
    works = bool(w.identity.verify(new, "crm.read"))
    old_still_dead = fails(lambda: w.identity.verify(old, "crm.read"))
    ok = held == ["agent-collect"] and old_dead and no_new and self_confirm and works and old_still_dead
    return ("held_until_recertified" if ok else "other"), {
        "agents_held": held, "old_token_dead": old_dead, "new_token_refused_while_held": no_new,
        "sponsor_cannot_confirm_own_agent": self_confirm, "after_new_approver_confirms_new_token_works": works,
        "old_token_still_dead": old_still_dead}


@case("I14")
def i14(det):
    w = World()
    _people(w)
    w.identity.register_agent("agent-a", "S003", {"crm.read", "email.draft"})
    w.identity.register_agent("agent-b", "S004", {"crm.read"})
    tok = w.identity.issue_token("agent-a")
    w.identity.verify(tok, "crm.read")
    w.clock.advance(days=20)
    w.identity.recertify_agent("agent-a", "S001")
    w.clock.advance(days=11)
    r = w.identity.access_review()
    a_active = w.identity.agents["agent-a"].status == "active"
    ok = r["unused_scopes"].get("agent-a") == ["email.draft"] and r["lapsed"] == ["agent-b"] and a_active
    return ("unused_scope_flagged_and_lapsed" if ok else "other"), {"review": r, "agent_a_still_active": a_active}


@case("I15")
def i15(det):
    w = World()
    try:
        w.identity.register_agent("agent-hr-mailer", "S003", {"hr.read", "email.send"})
        return "registered", {}
    except IdentityError as e:
        safe = w.identity.register_agent("agent-hr-drafter", "S003", {"hr.read", "email.draft"})
        return "refused", {"reason": str(e), "safer_combination_registered": bool(safe)}


@case("I16")
def i16(det):
    w = World()
    w.identity.register_agent("agent-collect", "S003", {"crm.read"})
    tok = w.identity.issue_token("agent-collect", audience="crm-api")
    right = bool(w.identity.verify(tok, "crm.read", audience="crm-api"))
    try:
        w.identity.verify(tok, "crm.read", audience="hr-api")
        return "accepted", {"right_service": right}
    except IdentityError as e:
        return "refused", {"right_service_accepts": right, "wrong_service": str(e)}


@case("I17")
def i17(det):
    w = World()
    _people(w)
    w.identity.register_agent("agent-helper", "S003", {"crm.read", "email.draft"})
    tok = w.identity.issue_token("agent-helper", on_behalf_of="S008", scopes={"crm.read"})
    before = bool(w.identity.verify(tok, "crm.read"))
    w.identity.person_left("S008")
    try:
        w.identity.verify(tok, "crm.read")
        return "still_valid", {"worked_before": before}
    except IdentityError as e:
        return "revoked", {"worked_before": before, "after_person_left": str(e),
                           "agent_itself_still_active": w.identity.agents["agent-helper"].status == "active"}


@case("I18")
def i18(det):
    w = World()
    w.identity.register_agent("agent-ops", "S004", {"db.read"})
    try:
        w.identity.request_privilege("agent-ops", "restart-service", "S001", approver_mfa_minutes_ago=45)
        stale = "accepted"
    except IdentityError as e:
        stale = str(e)
    g = w.identity.request_privilege("agent-ops", "restart-service", "S001", approver_mfa_minutes_ago=3)
    ok = stale != "accepted" and bool(g)
    return ("stale_refused_fresh_accepted" if ok else "other"), {"stale_45_min": stale, "fresh_3_min": g["id"]}


# Track E: more audit evidence

@case("E15")
def e15(det):
    w = World()
    c = w.customer(0)
    prompt = f"Write a catchy line for customer {c['name']}, Aadhaar {c['aadhaar']}, card {c['card']}, PAN {c['pan']}."
    d = ask(w, "U2", prompt)
    ask(w, "U1", prompt)
    text = json.dumps([l["body"] for l in w.log.lines])
    digits = text.replace(" ", "").replace("-", "")
    found = [k for k in ("aadhaar", "card", "pan", "name") if c[k].replace(" ", "").replace("-", "") in digits]
    return ("clean" if not found else "holds_personal_data"), {
        "first_request": f"{d.outcome}: {d.reason}", "log_lines": len(w.log.lines), "personal_values_found_in_log": found,
        "fields_logged": sorted({k for l in w.log.lines for k in l['body']})}


@case("E16")
def e16(det):
    w = World()
    ask(w, "U1")
    w.clock.advance(hours=1)
    ask(w, "U1")
    w.clock.now -= timedelta(days=2)       # the clock jumps back, or someone writes a line with an older date
    ask(w, "U1")
    chain_ok, bad = w.log.verify()
    ats = [l["body"]["at"] for l in w.log.lines]
    backwards = [i + 2 for i in range(len(ats) - 1) if ats[i + 1] < ats[i]]
    return ("chain_accepts_backdating" if chain_ok and backwards else "other"), {
        "hash_chain_verifies": chain_ok, "first_bad_line": bad,
        "lines_dated_earlier_than_the_line_before": backwards, "finding": "A hash chain proves order and content, not that dates make sense. Check dates against a trusted clock, and anchor the log's head somewhere else."}
