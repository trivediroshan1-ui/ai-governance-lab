from __future__ import annotations
"""Round ten: credential, session and identity edge cases (cases C1 to C12).
The expected results were committed in cases/round-10.json before this file existed.
Each function takes a detector (not used) and returns (outcome, details)."""
from .sessions import Accounts, App, BreakGlass, Directory, ErasableLog, Idp, proof
from .world import World

CASES = {}
KEY = b"client-private-key-stand-in"


def case(cid):
    def wrap(fn):
        CASES[cid] = fn
        return fn
    return wrap


@case("C1")
def c1(det):
    w = World(); idp = Idp(w.clock)
    plain = idp.issue("S002")
    bound = idp.issue("S002", client_key=KEY)
    plain_thief = App(idp, w.clock, require_proof=False).call(plain, "pay")[0]
    app = App(idp, w.clock, require_proof=True)
    bound_thief = app.call(bound, "pay")[0]
    bound_owner = app.call(bound, "pay", proof(KEY, bound, "pay"))[0]
    ok = plain_thief and not bound_thief and bound_owner
    return ("replayed_bound_refused" if ok else "other"), {"plain_token_works_for_thief": plain_thief, "bound_token_works_for_thief": bound_thief, "bound_token_works_for_owner": bound_owner}


@case("C2")
def c2(det):
    w = World(); idp = Idp(w.clock)
    bound = idp.issue("S002", client_key=KEY)
    thief_with_key = App(idp, w.clock, require_proof=True).call(bound, "pay", proof(KEY, bound, "pay"))[0]
    return ("not_caught" if thief_with_key else "other"), {"thief_with_token_and_key_accepted": thief_with_key, "limit": "a token tied to a key protects only while the key stays with its owner"}


@case("C3")
def c3(det):
    out = {}
    for name, mode in (("expiry_only", "none"), ("with_signal", "signed")):
        w = World(); idp = Idp(w.clock)
        app = App(idp, w.clock, signals=mode)
        tok = idp.issue("S002", minutes=60)
        w.clock.advance(minutes=10)
        app.receive(idp.signal("S002", "revoked"))
        w.clock.advance(minutes=1)
        out[name] = app.call(tok)[0]
    ok = out["expiry_only"] and not out["with_signal"]
    return ("works_until_expiry_signal_cuts" if ok else "other"), {"still_works_after_termination_expiry_only": out["expiry_only"], "still_works_after_termination_with_signal": out["with_signal"]}


@case("C4")
def c4(det):
    w = World(); idp = Idp(w.clock)
    app = App(idp, w.clock, signals="signed")
    tok = idp.issue("S002")
    first = app.receive(idp.signal("S002", "revoked", sign=False))
    still = app.call(tok)[0]
    second = app.receive(idp.signal("S002", "revoked"))
    after = app.call(tok)[0]
    ok = first == "refused_unsigned" and still and second == "applied" and not after
    return ("unsigned_ignored_signed_accepted" if ok else "other"), {"unsigned": first, "works_after_unsigned": still, "signed": second, "works_after_signed": after}


@case("C5")
def c5(det):
    out = {}
    for order in ("arrival", "time"):
        w = World(); idp = Idp(w.clock)
        app = App(idp, w.clock, ordering=order)
        tok = idp.issue("S002")
        t0 = w.clock()
        restored = idp.signal("S002", "restored", at=t0)
        w.clock.advance(minutes=5)
        revoked = idp.signal("S002", "revoked")
        app.receive(revoked); app.receive(restored)        # the older message arrives last
        out[order] = app.call(tok)[0]
    ok = out["arrival"] and not out["time"]
    return ("naive_reinstates_ordered_holds" if ok else "other"), {"last_to_arrive_wins_access_back_on": out["arrival"], "ordered_by_event_time_access_on": out["time"]}


@case("C6")
def c6(det):
    out = {}
    for mode in ("put", "patch"):
        d = Directory()
        d.create("u1", {"userName": "a@kaveri.example", "title": "Analyst", "active": False})
        d.sync_title("u1", "Senior analyst", mode)
        out[mode] = d.users["u1"]["active"]
    ok = out["put"] and not out["patch"]
    return ("put_reactivates_patch_holds" if ok else "other"), {"active_after_put": out["put"], "active_after_patch": out["patch"], "assumption": "a PUT without 'active' falls back to a server default of true, as many servers do"}


@case("C7")
def c7(det):
    out = {}
    for mode in ("restore", "fresh"):
        w = World(); a = Accounts(w.clock)
        a.by_key["S009"] = {"id": "S009", "name": "x", "job": "collections", "ent": set(BASELINE_COLL), "active": True}
        a.leave("S009"); w.clock.advance(days=40)
        out[mode] = sorted(a.rehire("S009", "support", mode)["ent"])
    ok = "collections-write" in out["restore"] and out["fresh"] == ["support-view"]
    return ("old_access_returns_fresh_holds" if ok else "other"), {"restored_account_has": out["restore"], "fresh_account_has": out["fresh"]}


BASELINE_COLL = {"support-view", "collections-write", "payments-view"}


@case("C8")
def c8(det):
    out = {}
    for match in ("name", "id"):
        w = World(); a = Accounts(w.clock)
        a.by_key["S009"] = {"id": "S009", "name": "Meera Rao", "email": "meera.rao@kaveri.example", "active": True, "ent": set(BASELINE_COLL)}
        a.sync_person({"id": "S009", "name": "Meera Iyer", "email": "meera.iyer@kaveri.example"}, match)
        out[match] = sum(1 for x in a.by_key.values() if x["id"] == "S009" and x["active"])
    ok = out["name"] == 2 and out["id"] == 1
    return ("duplicate_by_name_holds_by_id" if ok else "other"), {"active_accounts_matched_by_name": out["name"], "active_accounts_matched_by_id": out["id"]}


@case("C9")
def c9(det):
    out = {}
    for name, req in (("no_end_date", False), ("required_end_date", True)):
        w = World(); a = Accounts(w.clock)
        a.add_contractor("X1", "Staffing agency (made up)", None, require_end=req)
        w.clock.advance(days=120); a.sweep()
        out[name] = a.contractors["X1"]["active"]
    ok = out["no_end_date"] and not out["required_end_date"]
    return ("stays_active_hard_stop_holds" if ok else "other"), {"active_after_120_days_no_end_date": out["no_end_date"], "active_after_120_days_required_end_date": out["required_end_date"]}


@case("C10")
def c10(det):
    out = {}
    for name, ctl in (("no_controls", False), ("alert_and_rotate", True)):
        bg = BreakGlass(alert=ctl, rotate=ctl)
        old = bg.password
        bg.use("S021", old); bg.check_in()
        out[name] = {"people_told": len(bg.alerts), "old_password_works_after": bg.use("S099", old)}
    ok = out["no_controls"]["people_told"] == 0 and out["no_controls"]["old_password_works_after"] and out["alert_and_rotate"]["people_told"] == 1 and not out["alert_and_rotate"]["old_password_works_after"]
    return ("unnoticed_vs_alerted_and_rotated" if ok else "other"), out


@case("C11")
def c11(det):
    out = {}
    for name, pseudo in (("edit_the_line", False), ("pseudonym_store", True)):
        lg = ErasableLog(pseudo)
        for i in range(3):
            lg.write("Meera Rao", f"action {i}", f"2026-11-0{i + 2}T09:00:00+00:00")
        lg.write("Kabir Das", "other", "2026-11-05T09:00:00+00:00")
        lg.erase("Meera Rao")
        ok, bad = lg.log.verify()
        out[name] = {"chain_verifies": ok, "name_still_findable": lg.name_remains("Meera Rao")}
    ok = (not out["edit_the_line"]["chain_verifies"]) and out["pseudonym_store"]["chain_verifies"] and not out["pseudonym_store"]["name_still_findable"]
    return ("edit_breaks_chain_pseudonym_holds" if ok else "other"), out


@case("C12")
def c12(det):
    out = {}
    for name, limit in (("no_check", None), ("with_drift_check", 2)):
        w = World(); idp = Idp(w.clock)
        tok = idp.issue("S002", minutes=5)
        w.clock.advance(minutes=15)                       # the token expired 10 minutes ago
        out[name] = App(idp, w.clock, slow_by_minutes=15, drift_limit_minutes=limit).call(tok)
    ok = out["no_check"][0] and not out["with_drift_check"][0]
    return ("slow_clock_accepts_drift_check_refuses" if ok else "other"), {"slow_clock_accepts_expired_token": out["no_check"][0], "with_drift_check": out["with_drift_check"][1]}
