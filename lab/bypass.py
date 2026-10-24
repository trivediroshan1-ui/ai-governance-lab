from __future__ import annotations
"""Round eight: what if the agent goes around the gateway?

Small models written for this lab, added on top of the round-six plumbing:
- BoundApi: the identity API checks WHO is calling (a stand-in for tokens that
  only work from one caller, for example through mutual TLS), and keeps its own
  change log.
- Network: which source may reach which destination.
- reconcile / respond: compare the API's change log with the gateway's signed
  decisions; a change with no decision is a bypass. The policy then switches
  off the agent it can trace and leaves the change itself for a person.
- ListGate: allow / watch / block lists that depend on the state of the account.
- Delegates: a recorded helper for an employee who needs assistive technology.
- OffenceDesk: a signal goes to a named person with a copy of the evidence.
None of this is a real product, and the AI model behind an agent is not tested."""
import hashlib
import json
from datetime import timedelta

from .actions import EXECUTOR, ApiError, IdmApi
from .lifecycle import HR_ROLES, HrError

MOVER_DAYS = 30
WATCH_ACTIONS = {"read_user", "disable_user"}          # touching an account that is already off
BLOCK_ACTIONS = {"enable_user", "set_active", "reenable_user"}
ACCOMMODATION_CODES = {"alt_signin", "screen_reader_ui", "delegate"}     # codes only, never medical detail
AGENT_SOURCE = "agent-runtime"


class NetworkDenied(Exception):
    pass


class Network:
    def __init__(self, log, clock):
        self.log, self.clock = log, clock
        self.routes: set[tuple[str, str]] = set()

    def allow(self, src: str, dst: str) -> None:
        self.routes.add((src, dst))

    def call(self, src: str, dst: str, fn):
        if (src, dst) not in self.routes:
            self.log.append({"at": self.clock().isoformat(), "kind": "network", "action": "route_denied", "source": src, "destination": dst})
            raise NetworkDenied(f"no route from {src} to {dst}")
        return fn()


class BoundApi(IdmApi):
    """The identity API with a caller check and its own change log."""

    def _init_bound(self, enforce: bool = True, allowed=("executor",)):
        self.enforce = enforce
        self.allowed = set(allowed)
        self.source = "executor"
        self.audit: list[dict] = []

    def as_source(self, source: str):
        api = self

        class _Caller:
            def __getattr__(self, name):
                fn = getattr(api, name)

                def run(*a, **k):
                    old, api.source = api.source, source
                    try:
                        return fn(*a, **k)
                    finally:
                        api.source = old
                return run
        return _Caller()

    def _auth(self, token, password):
        if self.enforce and self.source not in self.allowed:
            raise ApiError(401, "caller not allowed to use this credential")
        super()._auth(token, password)

    def _note(self, method, uid, active=None, token=None):
        self.audit.append({"seq": len(self.audit) + 1, "method": method, "uid": uid, "active": active, "source": self.source,
                           "token_id": hashlib.sha256((token or "").encode()).hexdigest()[:8] if token else None})

    def create_user(self, attrs, token=None, password=None):
        r = super().create_user(attrs, token=token, password=password)
        self._note("POST", r["id"], True, token)
        return r

    def set_active(self, uid, active, token=None, password=None):
        r = super().set_active(uid, active, token=token, password=password)
        self._note("PATCH", uid, active, token)
        return r

    def delete_user(self, uid, token=None, password=None):
        r = super().delete_user(uid, token=token, password=password)
        self._note("DELETE", uid, None, token)
        return r

    def revoke_by_id(self, token_id: str) -> int:
        n = 0
        for t in list(self.tokens):
            if hashlib.sha256(t.encode()).hexdigest()[:8] == token_id and not self.tokens[t]["revoked"]:
                self.tokens[t]["revoked"] = True
                n += 1
        return n


def bind(p, enforce: bool = True) -> BoundApi:
    """Turn the plumbing's API into a BoundApi in place, so the vault, gateway and executor share it."""
    p.api.__class__ = BoundApi
    p.api._init_bound(enforce=enforce)
    p.net = Network(p.w.log, p.w.clock)
    p.net.allow("agent-runtime", "gateway")
    p.net.allow("executor", "idm-api")
    p.net.allow("executor", "vault")
    return p.api


def reconcile(p) -> dict:
    """Every change in the API's own log should match a decision the executor carried out for the gateway."""
    expected: dict[tuple, int] = {}
    for e in p.w.log.events(kind="executor", action="executed"):
        if e["requested"] == "create_user":
            key = ("POST", e["user_id"], True)
        elif e["requested"] == "disable_user":
            key = ("PATCH", e["user_id"], False)
        else:
            continue
        expected[key] = expected.get(key, 0) + 1
    unmatched = []
    for a in p.api.audit:
        key = (a["method"], a["uid"], a["active"])
        if expected.get(key, 0) > 0:
            expected[key] -= 1
        else:
            unmatched.append(a)
    p.w.log.append({"at": p.w.clock().isoformat(), "kind": "reconcile", "action": "run", "changes": len(p.api.audit), "unmatched": len(unmatched)})
    return {"changes": len(p.api.audit), "unmatched": unmatched}


def respond(p, report: dict, by: str = "policy") -> dict:
    """The kill-switch policy: switch off the agent the change can be traced to, revoke what it could use, leave the change for a person."""
    out = {"killed": [], "leaked_tokens_revoked": 0, "alert_only": 0}
    for a in report["unmatched"]:
        p.w.log.append({"at": p.w.clock().isoformat(), "kind": "bypass", "action": "alert", "change": a["seq"], "source": a["source"]})
        if a["source"].startswith(AGENT_SOURCE + ":"):
            agent = a["source"].split(":", 1)[1]
            if agent not in out["killed"]:
                out.setdefault("details", {})[agent] = p.kill(agent, by)
                out["killed"].append(agent)
            if a["token_id"]:
                out["leaked_tokens_revoked"] += p.api.revoke_by_id(a["token_id"])
        else:
            out["alert_only"] += 1
    return out


def sponsor_left(p, staff_id: str) -> dict:
    """A sponsor leaves: their agents stop, waiting requests are cancelled and lent credentials are revoked."""
    disabled = p.w.identity.sponsor_left(staff_id)
    out = {"disabled": disabled, "cancelled": 0, "leases_revoked": 0}
    for agent in disabled:
        out["cancelled"] += p.gateway.on_kill(agent)["cancelled"]
        out["leases_revoked"] += p.vault.revoke_for_agent(agent)
    return out


class ListGate:
    """Allow / watch / block lists that depend on what state the account is in. It sits in front of the gateway."""

    def __init__(self, p, lc=None):
        self.p, self.lc = p, lc
        self.movers: dict[str, dict] = {}

    def _rec(self, kind, action, **extra):
        self.p.w.log.append({"at": self.p.w.clock().isoformat(), "kind": kind, "action": action, **extra})

    def submit(self, req: dict, token: str) -> dict:
        action = req.get("action")
        tgt = req.get("target", {}) if isinstance(req.get("target"), dict) else {}
        uid = tgt.get("staff_id")
        if action in BLOCK_ACTIONS:
            self._rec("list", "block", requested=action, target=uid, why="needs a new HR event")
            return {"outcome": "blocked_by_list", "reason": "an account that was switched off stays off until a new HR event"}
        user = self.p.api.users.get(uid) if uid else None
        state = "disabled" if user is not None and not user["active"] else "active"
        if state == "disabled" and action in WATCH_ACTIONS:
            self._rec("list", "watch_alert", requested=action, target=uid, state=state)
        return self.p.gateway.submit(req, token)

    # movers
    def move(self, uid: str, new_job_code: str, birthright_new: set[str]) -> None:
        self.movers[uid] = {"since": self.p.w.clock(), "old": set(self.lc.roles.get(uid, set())), "new_birthright": set(birthright_new), "reviewed": False}
        self._rec("list", "mover_recorded", user=uid, job_code=new_job_code)

    def request_access(self, uid: str, role: str, manager: str) -> dict:
        rec = self.movers.get(uid)
        if rec and not rec["reviewed"]:
            self._rec("list", "block", user=uid, requested=role, why="old access not reviewed")
            return {"outcome": "blocked_by_list", "reason": "the old access has not been reviewed yet"}
        return self.lc.request_extra(uid, role, manager)

    def review_old(self, uid: str, reviewer: str) -> dict:
        who = self.p.w.identity.staff.get(reviewer)
        if not who or not who["active"] or who["role"] != "approver":
            return {"outcome": "refused", "reason": "only an active approver can review"}
        rec = self.movers[uid]
        self.lc.roles[uid] = set(rec["new_birthright"])
        rec["reviewed"] = True
        self._rec("list", "mover_old_access_removed", user=uid, reviewer=reviewer)
        return {"outcome": "reviewed"}

    def watch_scan(self) -> list[str]:
        now = self.p.w.clock()
        flagged = []
        for uid, rec in self.movers.items():
            if not rec["reviewed"] and now - rec["since"] >= timedelta(days=MOVER_DAYS):
                flagged.append(uid)
                self._rec("list", "watch_alert", user=uid, why="old access kept past 30 days")
        return flagged


class Delegates:
    """A helper (a reader, a caregiver, an assistant) who acts for an employee, recorded by HR."""

    def __init__(self, p):
        self.p = p
        self.pairs: set[tuple[str, str]] = set()

    def _rec(self, action, **extra):
        self.p.w.log.append({"at": self.p.w.clock().isoformat(), "kind": "delegate", "action": action, **extra})

    def register(self, employee: str, helper: str, approved_by: str, code: str) -> None:
        if not HR_ROLES.get(approved_by):
            raise HrError("only HR can record a helper")
        if code not in ACCOMMODATION_CODES:
            raise HrError("an accommodation is recorded as a code, never as free text")
        self.pairs.add((helper, employee))
        self._rec("registered", employee=employee, helper=helper, approved_by=approved_by, code=code)

    def act(self, helper: str, employee: str) -> str:
        if (helper, employee) in self.pairs:
            self._rec("acted_for", employee=employee, helper=helper)
            return "delegate"
        self._rec("watch_alert", employee=employee, actor=helper, why="actor is not a recorded helper")
        return "watch"


class OffenceDesk:
    """A rule raises a signal. A named person gets it with a copy of the evidence. The desk never decides anything."""

    def __init__(self, p):
        self.p = p

    @staticmethod
    def _hash(obj) -> str:
        return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def scan(self, activity: list[dict], notices: dict[str, str], big: int = 3, days: int = 7) -> list[dict]:
        signals = []
        for who, notice in notices.items():
            mine = [a for a in activity if a["who"] == who and a["kind"] == "export" and notice <= a["day"] <= _plus(notice, days)]
            if len(mine) >= big:
                signals.append({"rule": "R1-exports-after-notice", "who": who, "count": len(mine), "evidence": mine})
        return signals

    def open_case(self, signal: dict, owner: str, copied_by: str) -> dict:
        evidence = [dict(e) for e in signal["evidence"]]
        case = {"rule": signal["rule"], "who": signal["who"], "owner": owner, "status": "for_review",
                "evidence": evidence, "evidence_sha256": self._hash(evidence),
                "custody": [{"by": copied_by, "at": self.p.w.clock().isoformat(), "what": "copied from the activity log"}]}
        self.p.w.log.append({"at": self.p.w.clock().isoformat(), "kind": "offence_desk", "action": "case_opened", "rule": signal["rule"],
                             "owner": owner, "evidence_sha256": case["evidence_sha256"]})
        return case

    def verify(self, case: dict) -> bool:
        return self._hash(case["evidence"]) == case["evidence_sha256"]


def _plus(day: str, n: int) -> str:
    from datetime import date
    return (date.fromisoformat(day) + timedelta(days=n)).isoformat()
