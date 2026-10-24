from __future__ import annotations
"""Round twelve: a small approval queue written for the lab (cases F1 to F7).
It is a stand-in: no real approval product, no real people. Each switch below is one control."""
import hashlib
import json
from datetime import timedelta


def fingerprint(params: dict) -> str:
    return hashlib.sha256(json.dumps(params, sort_keys=True).encode()).hexdigest()[:16]


class Queue:
    HIGH_RISK_OVER = 100000      # an amount over this is high risk

    def __init__(self, clock, four_eyes=False, bind="number", ttl_hours=None, batch_excludes_high_risk=False,
                 reassign_on_leave=False, deny_wins=False, managers=None):
        self.clock = clock
        self.four_eyes, self.bind, self.ttl = four_eyes, bind, ttl_hours
        self.batch_excludes_high_risk, self.reassign_on_leave, self.deny_wins = batch_excludes_high_risk, reassign_on_leave, deny_wins
        self.managers = managers or {}
        self.reqs = {}
        self.active = {}          # person -> True while employed
        self.log = []

    def join(self, who):
        self.active[who] = True

    def leave(self, who):
        self.active[who] = False
        if self.reassign_on_leave:                    # control: pending work moves to the manager
            for r in self.reqs.values():
                if r["assigned"] == who and r["state"] == "pending":
                    r["assigned"] = self.managers[who]

    def request(self, rid, requester, params, assigned):
        self.reqs[rid] = {"requester": requester, "params": dict(params), "assigned": assigned, "state": "pending",
                          "votes": {}, "approved_fp": None, "approved_at": None}

    def edit(self, rid, new_params):
        self.reqs[rid]["params"] = dict(new_params)

    def vote(self, rid, approver, verdict):
        r = self.reqs[rid]
        if not self.active.get(approver):
            return "refused_not_active"
        if self.four_eyes and approver == r["requester"]:         # control: someone else must approve
            return "refused_self"
        r["votes"][approver] = verdict
        if verdict == "approve":
            r["approved_fp"] = fingerprint(r["params"])
            r["approved_at"] = self.clock()
            r["state"] = "approved"
        return "recorded"

    def batch_approve(self, rids, approver):
        done, held = [], []
        for rid in rids:
            r = self.reqs[rid]
            if self.batch_excludes_high_risk and r["params"].get("amount", 0) > self.HIGH_RISK_OVER:   # control
                held.append(rid)
                continue
            self.vote(rid, approver, "approve")
            done.append(rid)
        return done, held

    def can_act(self, rid, approver):
        """Whether this approver is allowed to act on a pending request that sits in a queue."""
        r = self.reqs[rid]
        return r["assigned"] == approver and bool(self.active.get(approver))

    def run(self, rid):
        r = self.reqs[rid]
        if r["state"] != "approved":
            return "not_approved"
        if self.deny_wins and "deny" in r["votes"].values():          # control: one denial stops it
            return "refused_denied"
        if self.ttl is not None and self.clock() - r["approved_at"] > timedelta(hours=self.ttl):   # control
            return "refused_expired"
        if self.bind == "hash" and fingerprint(r["params"]) != r["approved_fp"]:                   # control
            return "refused_changed"
        r["state"] = "ran"
        return "ran"
