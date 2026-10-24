from __future__ import annotations
"""Round seven: the HR side of identity onboarding.

A person or vendor becomes an identity only after HR approves a hire event.
The HR system is the source of truth. The identity governance tool (here,
Lifecycle) turns an approved event into a directory account and gives only
the access that policy attaches to the job code. An agent may check data,
propose extra access and send the create request, but the gateway refuses a
create request that no approved HR event backs.

HR, the identity governance tool and the directory are small models written
for this lab. They are not Workday, SailPoint, Entra or Active Directory."""
import hashlib
from datetime import date, timedelta

from .actions import API_TOKEN_PATH, ApiError

# People in HR (made up). One of them can hold both approval roles, to test separation of duties.
HR_ROLES = {"HR-TA-1": {"ta_hr"}, "HR-TA-2": {"ta_hr"}, "HR-BU-1": {"bu_hr"}, "HR-BU-2": {"bu_hr"}, "HR-DUAL-1": {"ta_hr", "bu_hr"}}
BIRTHRIGHT = {"LOAN-OFFICER": {"crm.read", "loan.create"}, "SUPPORT-AGENT": {"crm.read", "tickets.write"}, "VENDOR-TESTER": {"tickets.read"}}
REQUESTABLE = {"reports.export", "loan.view", "loan.approve"}      # may be asked for, with the manager's approval
TOXIC_ROLES = [({"loan.create"}, {"loan.approve"})]
EVENT_FIELDS = ("given_name", "family_name", "email", "team")      # what a create request must match
SENSITIVE_APP = "treasury-portal"


class HrError(Exception):
    pass


def _h(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


class Hr:
    def __init__(self, log, clock):
        self.log, self.clock = log, clock
        self.records: dict[str, dict] = {}
        self.events: dict[str, dict] = {}
        self.known_pan_hashes: dict[str, str] = {}      # PAN hash -> existing employee
        self.n = 0

    def _record(self, action: str, **extra):
        self.log.append({"at": self.clock().isoformat(), "kind": "hr", "action": action, **extra})

    def add_prehire(self, rec: dict) -> str:
        self.n += 1
        rid = f"PH-{self.n:04d}"
        r = {"id": rid, "kind": rec.get("kind", "employee"), "approvals": {}, "bgv": rec.get("bgv", "pending"), "hold": None,
             "cancelled": False, **rec}
        pan = r.get("pan")
        if pan:
            h = _h(pan)
            r["pan_hash"] = h
            others = [x["id"] for x in self.records.values() if x.get("pan_hash") == h]
            if h in self.known_pan_hashes or others:
                r["hold"] = "duplicate_pan"
                self._record("prehire_held_duplicate", record=rid)
        self.records[rid] = r
        self._record("prehire_added", record=rid, kind=r["kind"])
        return rid

    def set_bgv(self, rid: str, status: str) -> None:
        self.records[rid]["bgv"] = status
        self._record("bgv_recorded", record=rid, status=status)

    def approve(self, rid: str, who: str, as_role: str) -> None:
        r = self.records[rid]
        if as_role not in HR_ROLES.get(who, set()):
            raise HrError(f"{who} cannot approve as {as_role}")
        if who in r["approvals"].values():
            self._record("approval_refused_same_person", record=rid, who=who)
            raise HrError("the same person cannot give both approvals")
        r["approvals"][as_role] = who
        self._record("hr_approved", record=rid, who=who, role=as_role)

    def clear_hold(self, rid: str, who: str) -> None:
        if not HR_ROLES.get(who):
            raise HrError("only HR can clear a hold")
        self.records[rid]["hold"] = None
        self._record("hold_cleared", record=rid, who=who)

    def cancel(self, rid: str) -> None:
        self.records[rid]["cancelled"] = True
        self._record("offer_withdrawn", record=rid)

    def why_not(self, rid: str) -> str | None:
        r = self.records[rid]
        if r["cancelled"]:
            return "the offer was withdrawn"
        if r["hold"]:
            return f"held for HR review ({r['hold']})"
        if r["kind"] == "employee":
            if r["bgv"] != "clear":
                return f"background verification is {r['bgv']}"
            if set(r["approvals"]) != {"ta_hr", "bu_hr"}:
                return "needs talent acquisition HR and BU HR, two different people"
        else:
            if not r.get("sponsor"):
                return "a vendor worker needs a named sponsor"
            if not r.get("end_date"):
                return "a vendor worker needs an end date"
            if not r.get("tprm_ok"):
                return "the vendor's security review is not done"
            if "bu_hr" not in r["approvals"]:
                return "needs BU approval"
        return None

    def hire_event(self, rid: str) -> dict | None:
        """The only trigger for an account. Contains only what identity needs."""
        if self.why_not(rid):
            return None
        for e in self.events.values():
            if e["record"] == rid:
                return e
        r = self.records[rid]
        eid = f"HE-{len(self.events) + 1:04d}"
        ev = {"event_id": eid, "record": rid, "kind": r["kind"], **{k: r[k] for k in EVENT_FIELDS}, "job_code": r["job_code"],
              "manager": r["manager"], "start_date": r["start_date"]}
        if r["kind"] == "vendor":
            ev["sponsor"], ev["end_date"] = r["sponsor"], r["end_date"]
        self.events[eid] = ev
        self._record("hire_event_issued", event=eid, record=rid, approved_by=sorted(r["approvals"].values()))
        return ev


class Lifecycle:
    """The identity governance side: turns approved events into accounts, switches them on and off on the right dates."""

    def __init__(self, plumbing):
        self.p = plumbing
        self.w = plumbing.w
        self.hr = Hr(self.w.log, self.w.clock)
        self.roles: dict[str, set[str]] = {}
        self.activated: set[str] = set()
        self.disabled_by_iga: dict[str, str] = {}
        self.mfa: set[str] = set()
        self.policy_signed: set[str] = set()
        self.peers: dict[str, list[set[str]]] = {}
        plumbing.gateway.hr_check = self.gateway_check
        plumbing.vault.allow("iga-connector", API_TOKEN_PATH)
        plumbing.vault.allow("it-admin", API_TOKEN_PATH)

    def _record(self, action: str, **extra):
        self.w.log.append({"at": self.w.clock().isoformat(), "kind": "iga", "action": action, **extra})

    # Gateway hook: no create request without an approved event that matches it
    def gateway_check(self, req: dict) -> tuple[bool, str]:
        eid = req.get("hire_event")
        ev = self.hr.events.get(eid) if isinstance(eid, str) else None
        if ev is None:
            return False, "no approved HR hire event backs this request"
        if self.hr.records[ev["record"]]["cancelled"]:
            return False, "the hire event was withdrawn"
        if any(req["target"].get(k) != ev[k] for k in EVENT_FIELDS):
            return False, "the request does not match the hire event"
        return True, ""

    def _lease(self, who: str, fn):
        lid, tok = self.p.vault.lease_api_token(who, f"iga-{self.w.clock().timestamp():.0f}", who)
        try:
            return fn(tok)
        finally:
            self.p.vault.revoke_lease(lid, why="checked_in")

    def account_for(self, ev: dict) -> str | None:
        for uid, u in self.p.api.users.items():
            if u["userName"] == ev["email"]:
                return uid
        return None

    def sync(self) -> dict:
        """The daily job: dates and withdrawals decide whether each account is on or off."""
        today = self.w.clock().date().isoformat()
        out = {"enabled": [], "disabled": [], "expired": []}
        for ev in self.hr.events.values():
            uid = self.account_for(ev)
            if uid is None:
                continue
            u = self.p.api.users[uid]
            rec = self.hr.records[ev["record"]]
            if rec["cancelled"]:
                if u["active"]:
                    self._lease("iga-connector", lambda t: self.p.api.set_active(uid, False, token=t))
                    self._record("disabled_offer_withdrawn", user=uid, event=ev["event_id"])
                    out["disabled"].append(uid)
                self.disabled_by_iga[uid] = "withdrawn"
                continue
            if ev["kind"] == "vendor" and ev["end_date"] <= today:
                if u["active"]:
                    self._lease("iga-connector", lambda t: self.p.api.set_active(uid, False, token=t))
                    self._record("disabled_end_date", user=uid, event=ev["event_id"])
                    out["expired"].append(uid)
                self.disabled_by_iga[uid] = "expired"
                continue
            if ev["start_date"] > today:
                if u["active"]:
                    self._lease("iga-connector", lambda t: self.p.api.set_active(uid, False, token=t))
                    self._record("held_until_start", user=uid, event=ev["event_id"], start=ev["start_date"])
                    out["disabled"].append(uid)
                continue
            if uid not in self.activated:
                self._lease("iga-connector", lambda t: self.p.api.set_active(uid, True, token=t))
                self.roles[uid] = set(BIRTHRIGHT.get(ev["job_code"], set()))
                self.activated.add(uid)
                self._record("enabled_on_start", user=uid, event=ev["event_id"], roles=sorted(self.roles[uid]))
                out["enabled"].append(uid)
        return out

    # Day one
    def enrol_mfa(self, uid: str) -> None:
        self.mfa.add(uid)
        self._record("mfa_enrolled", user=uid)

    def sign_policy(self, uid: str) -> None:
        self.policy_signed.add(uid)
        self._record("policy_signed", user=uid)

    def open_sensitive_app(self, uid: str) -> tuple[bool, str]:
        u = self.p.api.users.get(uid)
        if not u or not u["active"]:
            return False, "the account is not active"
        if uid not in self.mfa:
            self._record("app_refused_no_mfa", user=uid, app=SENSITIVE_APP)
            return False, "MFA is not enrolled"
        if uid not in self.policy_signed:
            self._record("app_refused_no_policy", user=uid, app=SENSITIVE_APP)
            return False, "the acceptable-use policy is not signed"
        return True, "ok"

    # Extra access: the agent proposes from peer patterns, people decide
    def propose_extras(self, uid: str, job_code: str, threshold: float = 0.5) -> list[str]:
        """A plain majority count over peers with the same job code. Not a model. It proposes and changes nothing."""
        peers = self.peers.get(job_code, [])
        have = self.roles.get(uid, set())
        counts: dict[str, int] = {}
        for pr in peers:
            for r in pr:
                counts[r] = counts.get(r, 0) + 1
        return sorted(r for r, n in counts.items() if n / max(1, len(peers)) >= threshold and r not in have)

    def request_extra(self, uid: str, role: str, manager: str) -> dict:
        if role not in REQUESTABLE:
            return {"outcome": "refused", "reason": "not a requestable role"}
        have = self.roles.get(uid, set())
        for a, b in TOXIC_ROLES:
            if (a <= have and b <= {role}) or (b <= have and a <= {role}):
                self._record("extra_refused_toxic", user=uid, role=role)
                return {"outcome": "refused", "reason": "toxic combination with a role already held"}
        mgr = self.w.identity.staff.get(manager)
        if not mgr or not mgr["active"]:
            return {"outcome": "refused", "reason": "the manager is not active"}
        self.roles.setdefault(uid, set()).add(role)
        self._record("extra_granted", user=uid, role=role, approved_by=manager)
        return {"outcome": "granted", "role": role}

    # Auditor's check: every account traces to an HR record
    def reconcile(self) -> dict:
        hr_known = {s["id"] for s in self.w.staff}
        emails = {ev["email"] for ev in self.hr.events.values()}
        orphans = sorted(uid for uid, u in self.p.api.users.items() if uid not in hr_known and u["userName"] not in emails)
        return {"orphans": orphans, "accounts": len(self.p.api.users), "hr_events": len(self.hr.events)}
