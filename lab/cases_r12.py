from __future__ import annotations
"""Round twelve: approvals (cases F1 to F7). The expected results were committed in
cases/round-12.json before this file existed. The queue is a small model (lab/approvals.py).
Each function takes a detector (not used) and returns (outcome, details)."""
from datetime import datetime, timedelta

from .approvals import Queue

CASES = {}
T0 = datetime(2026, 10, 26, 9, 0)


def case(cid):
    def wrap(fn):
        CASES[cid] = fn
        return fn
    return wrap


class Clock:
    def __init__(self):
        self.t = T0

    def __call__(self):
        return self.t

    def advance(self, **kw):
        self.t += timedelta(**kw)


def _q(**kw):
    c = Clock()
    q = Queue(c, **kw)
    for p in ("meera", "arun", "kiran", "dev", "isha"):
        q.join(p)
    return c, q


@case("F1")
def f1(det):
    _, q = _q(four_eyes=False)
    q.request("R1", "meera", {"payee": "Vendor A", "amount": 40000}, "meera")
    no_rule = q.vote("R1", "meera", "approve") == "recorded" and q.run("R1") == "ran"
    _, q2 = _q(four_eyes=True)
    q2.request("R1", "meera", {"payee": "Vendor A", "amount": 40000}, "meera")
    refused = q2.vote("R1", "meera", "approve") == "refused_self" and q2.run("R1") == "not_approved"
    return ("self_approval_accepted_four_eyes_holds" if no_rule and refused else "other"), {"self_approval_ran_without_rule": no_rule, "refused_with_rule": refused}


def _f2(bind):
    _, q = _q(bind=bind)
    q.request("R2", "meera", {"payee": "Vendor A", "amount": 40000}, "arun")
    q.vote("R2", "arun", "approve")
    q.edit("R2", {"payee": "Vendor A", "amount": 4000000})
    return q.run("R2")


@case("F2")
def f2(det):
    a, b = _f2("number"), _f2("hash")
    return ("edit_after_approval_runs_hash_binding_holds" if a == "ran" and b == "refused_changed" else "other"), {"tied_to_number": a, "tied_to_fingerprint": b}


def _f3(excl):
    _, q = _q(batch_excludes_high_risk=excl)
    ids = []
    for i in range(20):
        rid = f"B{i}"
        q.request(rid, "meera", {"payee": f"V{i}", "amount": 5000}, "arun")
        ids.append(rid)
    q.edit("B13", {"payee": "V13", "amount": 900000})
    done, held = q.batch_approve(ids, "arun")
    return q.run("B13"), len(done), len(held)


@case("F3")
def f3(det):
    a, b = _f3(False), _f3(True)
    ok = a[0] == "ran" and b[0] == "not_approved" and b[2] == 1
    return ("batch_passes_bad_item_cap_holds" if ok else "other"), {"no_limit": {"big_item": a[0], "approved": a[1]}, "high_risk_excluded": {"big_item": b[0], "held_back": b[2]}}


def _f4(ttl):
    c, q = _q(ttl_hours=ttl)
    q.request("R4", "meera", {"payee": "Vendor A", "amount": 40000}, "arun")
    q.vote("R4", "arun", "approve")
    c.advance(days=3)
    return q.run("R4")


@case("F4")
def f4(det):
    a, b = _f4(None), _f4(24)
    return ("stale_approval_runs_expiry_holds" if a == "ran" and b == "refused_expired" else "other"), {"no_expiry": a, "expires_in_24h": b}


def _f5(reassign):
    _, q = _q(reassign_on_leave=reassign, managers={"arun": "kiran"})
    q.request("R5", "meera", {"payee": "Vendor A", "amount": 40000}, "arun")
    q.leave("arun")
    r = q.reqs["R5"]
    return q.can_act("R5", "kiran"), r["assigned"]


@case("F5")
def f5(det):
    a, b = _f5(False), _f5(True)
    ok = (not a[0]) and a[1] == "arun" and b[0] and b[1] == "kiran"
    return ("queue_stuck_reassign_holds" if ok else "other"), {"stays_with_leaver": {"manager_can_act": a[0], "assigned_to": a[1]}, "reassigned": {"manager_can_act": b[0], "assigned_to": b[1]}}


def _f6(deny_wins):
    _, q = _q(deny_wins=deny_wins)
    q.request("R6", "meera", {"payee": "Vendor A", "amount": 40000}, "arun")
    q.vote("R6", "arun", "deny")
    q.vote("R6", "dev", "approve")
    return q.run("R6")


@case("F6")
def f6(det):
    a, b = _f6(False), _f6(True)
    return ("approve_beats_deny_deny_wins_holds" if a == "ran" and b == "refused_denied" else "other"), {"any_one_approval": a, "deny_wins": b}


@case("F7")
def f7(det):
    _, q = _q(four_eyes=True, bind="hash", ttl_hours=24, batch_excludes_high_risk=True, deny_wins=True)
    q.request("X1", "meera", {"payee": "Meera's cousin", "amount": 50000}, "arun")
    q.request("X2", "arun", {"payee": "Arun's cousin", "amount": 50000}, "meera")
    q.vote("X1", "arun", "approve")
    q.vote("X2", "meera", "approve")
    both = q.run("X1") == "ran" and q.run("X2") == "ran"
    return ("not_caught" if both else "other"), {"both_ran_with_every_rule_on": both}
