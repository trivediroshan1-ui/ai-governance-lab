from __future__ import annotations
"""Round six: an agent sends an instruction, it does not act directly.

The agent proposes a structured request. A gateway outside the agent checks
the agent's identity, the request shape, the policy, the rate and (for risky
actions) a human approval. Only then does it sign a decision. A separate
executor, with its own identity, checks the signature, takes a short-lived
credential from a vault and calls the identity API. The agent never holds the
credential.

The vault and the identity API here are small models written for this lab.
They are not HashiCorp Vault, Delinea Secret Server or any SCIM product, and
the model that powers an agent is not tested: cases assume the agent was
fooled or wrong and test the wall around it."""
import hashlib
import hmac
import json
import re
import secrets
from datetime import timedelta

from .hashlog import HashLog
from .identity import IdentityError, IdentityService

GATEWAY_AUDIENCE = "idm-gateway"
LEASE_MINUTES = 5
DECISION_MINUTES = 10
RATE_WINDOW_MINUTES = 60
EXECUTOR = "executor-idm"
API_TOKEN_PATH = "idm/api-token"
API_PASSWORD_PATH = "idm/service-password"


class VaultError(Exception):
    pass


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"{status} {message}")
        self.status = status


class ExecError(Exception):
    pass


# The identity API (a small stand-in for a SCIM-style service)

class IdmApi:
    def __init__(self, staff: list[dict], clock):
        self.clock = clock
        self.users = {s["id"]: {"id": s["id"], "userName": s["email"], "displayName": s["name"],
                                "team": s["team"], "active": True} for s in staff}
        self.tokens: dict[str, dict] = {}
        self.password: str | None = None
        self.next_id = 1001
        self.calls: list[dict] = []

    def accept_token(self, token: str, expires) -> None:
        self.tokens[token] = {"expires": expires, "revoked": False}

    def revoke_token(self, token: str) -> None:
        if token in self.tokens:
            self.tokens[token]["revoked"] = True

    def set_password(self, password: str) -> None:
        self.password = password

    def _auth(self, token, password):
        if token is not None:
            t = self.tokens.get(token)
            if t is None or t["revoked"] or t["expires"] <= self.clock():
                raise ApiError(401, "credential not accepted")
        elif password is not None:
            if self.password is None or not hmac.compare_digest(password, self.password):
                raise ApiError(401, "credential not accepted")
        else:
            raise ApiError(401, "no credential")

    def create_user(self, attrs: dict, token=None, password=None) -> dict:      # POST /Users
        self._auth(token, password)
        uid = f"N{self.next_id}"
        self.next_id += 1
        self.users[uid] = {"id": uid, "userName": attrs["email"], "displayName": f"{attrs['given_name']} {attrs['family_name']}",
                           "team": attrs["team"], "active": True}
        self.calls.append({"method": "POST", "path": "/Users", "id": uid})
        return {"id": uid}

    def set_active(self, uid: str, active: bool, token=None, password=None) -> dict:      # PATCH /Users/{id}
        self._auth(token, password)
        if uid not in self.users:
            raise ApiError(404, "no such user")
        self.users[uid]["active"] = active
        self.calls.append({"method": "PATCH", "path": f"/Users/{uid}", "active": active})
        return {"id": uid, "active": active}

    def get_user(self, uid: str, token=None, password=None) -> dict:      # GET /Users/{id}
        self._auth(token, password)
        if uid not in self.users:
            raise ApiError(404, "no such user")
        return dict(self.users[uid])

    def delete_user(self, uid: str, token=None, password=None) -> dict:      # DELETE /Users/{id}
        self._auth(token, password)
        self.users.pop(uid, None)
        self.calls.append({"method": "DELETE", "path": f"/Users/{uid}"})
        return {"id": uid, "deleted": True}


# The vault (a model of leases and check-out, not a real product)

class Vault:
    def __init__(self, log: HashLog, clock, api: IdmApi):
        self.log, self.clock, self.api = log, clock, api
        self.policy: dict[str, set[str]] = {}       # identity -> paths it may read
        self.leases: dict[str, dict] = {}
        self.issued: list[str] = []                 # every secret ever handed out (for the lab's own leak scan)
        self._password = secrets.token_hex(10)
        self.api.set_password(self._password)
        self.checked_out_by: str | None = None
        self.issued.append(self._password)

    def _record(self, action: str, **extra):
        self.log.append({"at": self.clock().isoformat(), "kind": "vault", "action": action, **extra})

    def allow(self, identity: str, *paths: str) -> None:
        self.policy.setdefault(identity, set()).update(paths)

    def _check(self, identity: str, path: str) -> None:
        if path not in self.policy.get(identity, set()):
            self._record("vault_denied", identity=identity, path=path)
            raise VaultError(f"{identity} may not read {path}")

    def lease_api_token(self, identity: str, request_id: str, agent: str, minutes: int = LEASE_MINUTES) -> tuple[str, str]:
        self._check(identity, API_TOKEN_PATH)
        token = "idmtok_" + secrets.token_hex(12)
        lid = "L-" + secrets.token_hex(4)
        expires = self.clock() + timedelta(minutes=minutes)
        self.leases[lid] = {"token": token, "identity": identity, "request": request_id, "agent": agent,
                            "expires": expires, "revoked": False}
        self.api.accept_token(token, expires)
        self.issued.append(token)
        self._record("lease_issued", lease=lid, identity=identity, request=request_id, agent=agent, minutes=minutes)
        return lid, token

    def revoke_lease(self, lid: str, why: str = "checked_in") -> None:
        lease = self.leases[lid]
        lease["revoked"] = True
        self.api.revoke_token(lease["token"])
        self._record("lease_revoked", lease=lid, why=why)

    def revoke_for_agent(self, agent: str) -> int:
        n = 0
        for lid, lease in self.leases.items():
            if lease["agent"] == agent and not lease["revoked"]:
                self.revoke_lease(lid, why="kill_switch")
                n += 1
        return n

    def checkout_password(self, identity: str) -> str:
        self._check(identity, API_PASSWORD_PATH)
        self.checked_out_by = identity
        self._record("password_checked_out", identity=identity)
        return self._password

    def checkin_password(self, identity: str) -> None:
        if self.checked_out_by != identity:
            raise VaultError("Not checked out by this identity.")
        self._password = secrets.token_hex(10)
        self.issued.append(self._password)
        self.api.set_password(self._password)
        self.checked_out_by = None
        self._record("password_checked_in_and_rotated", identity=identity)


# The policy table

ACTIONS = {
    "create_user":  {"scope": "idm.user.create",  "approval": False, "limit": 10},
    "disable_user": {"scope": "idm.user.disable", "approval": True,  "limit": 5},
    "read_user":    {"scope": "idm.user.read",    "approval": False, "limit": 50},
}
NOT_OFFERED = {"delete_user", "reset_admin_password", "add_to_admin_group", "export_all_users"}
REQUIRED = {"request_id", "action", "target"}
OPTIONAL = {"reason", "hire_event"}
CREATE_FIELDS = {"given_name", "family_name", "email", "team"}
STAFF_ID = re.compile(r"^[SN][0-9]{3,4}$")


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _short_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def validate(req) -> str | None:
    """Return a reason if the request's shape is wrong, else None."""
    if not isinstance(req, dict):
        return "request must be an object"
    extra = set(req) - REQUIRED - OPTIONAL
    if extra:
        return f"fields not allowed: {sorted(extra)}"
    missing = REQUIRED - set(req)
    if missing:
        return f"missing fields: {sorted(missing)}"
    if not isinstance(req["request_id"], str) or not 3 <= len(req["request_id"]) <= 40:
        return "request_id must be a short string"
    reason = req.get("reason", "")
    if not isinstance(reason, str) or len(reason) > 200:
        return "reason must be text of at most 200 characters"
    tgt = req["target"]
    if not isinstance(tgt, dict):
        return "target must be an object"
    if req["action"] == "create_user":
        if set(tgt) != CREATE_FIELDS or not all(isinstance(v, str) and 0 < len(v) <= 80 for v in tgt.values()):
            return "create_user target must hold exactly given_name, family_name, email, team as short text"
    else:
        if set(tgt) != {"staff_id"} or not isinstance(tgt["staff_id"], str) or not STAFF_ID.match(tgt["staff_id"]):
            return "target must hold exactly one staff_id such as S014"
    return None


# The gateway: checks everything, signs the decision

class ActionGateway:
    def __init__(self, identity: IdentityService, api: IdmApi, log: HashLog, clock):
        self.identity, self.api, self.log, self.clock = identity, api, log, clock
        self._key = secrets.token_bytes(32)
        self.pending: dict[str, dict] = {}
        self.accepted: list[dict] = []            # (agent, action, time) for rate limits
        self.executor: "Executor | None" = None
        self.agent_view: list[dict] = []          # every reply the agent has been shown
        self.hr_check = None                      # round seven: a function that says whether an approved HR event backs a create_user request

    def _record(self, action: str, **extra):
        self.log.append({"at": self.clock().isoformat(), "kind": "action_gateway", "action": action, **extra})

    def _reply(self, **r) -> dict:
        self.agent_view.append(r)
        return r

    # Signing is the gateway's alone. The executor holds the same key to check it
    # (a real system would use a public-key signature or mutual TLS instead).
    def signing_key_for_executor(self) -> bytes:
        return self._key

    def sign(self, decision: dict) -> dict:
        body = {k: v for k, v in decision.items() if k != "sig"}
        return {**body, "sig": hmac.new(self._key, _canon(body).encode(), hashlib.sha256).hexdigest()}

    def _decide(self, req: dict, agent: str, approved_by: str | None) -> dict:
        d = {"request_id": req["request_id"], "action": req["action"], "target": req["target"], "agent": agent,
             "approved_by": approved_by, "expires": (self.clock() + timedelta(minutes=DECISION_MINUTES)).isoformat()}
        return self.sign(d)

    def submit(self, req, token: str) -> dict:
        action = req.get("action") if isinstance(req, dict) else None
        try:
            claims = self.identity.verify(token, "idm.gateway", audience=GATEWAY_AUDIENCE)
        except IdentityError as e:
            self._record("request_refused_identity", reason=str(e))
            return self._reply(outcome="refused", reason=str(e))
        agent = claims["sub"]
        rid = req.get("request_id") if isinstance(req, dict) else None
        if not isinstance(action, str) or len(action) > 40:
            self._record("request_rejected", agent=agent, why="action is not one of the listed actions")
            return self._reply(outcome="rejected", reason="action must be one of the listed actions")
        if action in NOT_OFFERED:
            self._record("request_blocked", agent=agent, request=rid, requested=action)
            return self._reply(outcome="blocked", reason=f"{action} is not offered to agents")
        spec = ACTIONS.get(action)
        if spec is None:
            self._record("request_rejected", agent=agent, request=rid, why="unknown action")
            return self._reply(outcome="rejected", reason="action must be one of the listed actions")
        if spec["scope"] not in claims["scp"]:
            self._record("scope_denied_at_gateway", agent=agent, request=rid, requested=action, scope=spec["scope"])
            return self._reply(outcome="refused", reason=f"this agent's token does not carry {spec['scope']}")
        bad = validate(req)
        if bad:
            self._record("request_rejected", agent=agent, request=rid, requested=action, why=bad)
            return self._reply(outcome="rejected", reason=bad)
        if action == "create_user" and self.hr_check is not None:
            ok, why = self.hr_check(req)
            if not ok:
                self._record("request_refused_no_hr_event", agent=agent, request=rid, why=why)
                return self._reply(outcome="refused", reason=why)
        now = self.clock()
        recent = [a for a in self.accepted if a["agent"] == agent and a["action"] == action
                  and now - a["at"] <= timedelta(minutes=RATE_WINDOW_MINUTES)]
        if len(recent) >= spec["limit"]:
            self._record("request_rate_limited", agent=agent, request=rid, requested=action, limit=spec["limit"])
            return self._reply(outcome="rate_limited", reason=f"more than {spec['limit']} {action} requests in {RATE_WINDOW_MINUTES} minutes")
        self.accepted.append({"agent": agent, "action": action, "at": now})
        reason_text = req.get("reason", "")
        self._record("request_accepted", agent=agent, request=rid, requested=action, target=self._log_target(req), hire_event=req.get("hire_event"),
                     reason_hash=_short_hash(reason_text), reason_length=len(reason_text))
        if spec["approval"]:
            self.pending[rid] = {"req": req, "agent": agent, "at": now}
            return self._reply(outcome="pending_approval", request_id=rid)
        return self._reply(**self._run(req, agent, None))

    @staticmethod
    def _log_target(req: dict):
        # The log keeps who and what, never names, e-mail addresses or free text.
        if req["action"] == "create_user":
            return {"attributes_hash": _short_hash(_canon(req["target"]))}
        return req["target"]

    def approval_screen(self, rid: str) -> dict:
        """What the approver is shown: the request and the record it points to."""
        p = self.pending[rid]
        u = self.api.users.get(p["req"]["target"].get("staff_id", ""), {})
        return {"request_id": rid, "action": p["req"]["action"], "agent": p["agent"],
                "target_id": p["req"]["target"].get("staff_id"), "target_name": u.get("displayName"),
                "target_team": u.get("team"), "reason": p["req"].get("reason", "")}

    def approve(self, rid: str, approver: str) -> dict:
        p = self.pending.get(rid)
        if p is None:
            return self._reply(outcome="refused", reason="no such pending request")
        agent = self.identity.agents.get(p["agent"])
        person = self.identity.staff.get(approver)
        if agent is None or agent.status != "active":
            self.pending.pop(rid, None)
            self._record("approval_refused_agent_not_active", request=rid, agent=p["agent"])
            return self._reply(outcome="refused", reason="the agent is no longer active")
        if person is None or not person["active"] or person["role"] != "approver":
            self._record("approval_refused_not_an_approver", request=rid, who=approver)
            return self._reply(outcome="refused", reason="only an active approver can approve")
        if approver == agent.sponsor:
            self._record("approval_refused_sponsor", request=rid, who=approver)
            return self._reply(outcome="refused", reason="the agent's own sponsor cannot approve its requests")
        self.pending.pop(rid)
        self._record("approved", request=rid, approver=approver)
        return self._reply(**self._run(p["req"], p["agent"], approver))

    def _run(self, req: dict, agent: str, approver: str | None) -> dict:
        assert self.executor is not None
        decision = self._decide(req, agent, approver)
        return self.executor.execute(decision)

    def on_kill(self, agent: str) -> dict:
        cancelled = [r for r, p in self.pending.items() if p["agent"] == agent]
        for r in cancelled:
            self.pending.pop(r)
        self._record("agent_killed_pending_cancelled", agent=agent, cancelled=len(cancelled))
        return {"cancelled": len(cancelled)}


# The executor: ordinary code, its own identity, the only holder of API credentials

class Executor:
    def __init__(self, gateway: ActionGateway, vault: Vault, api: IdmApi, log: HashLog, clock):
        self.gateway, self.vault, self.api, self.log, self.clock = gateway, vault, api, log, clock
        self._key = gateway.signing_key_for_executor()
        self.done: dict[str, dict] = {}
        gateway.executor = self

    def _record(self, action: str, **extra):
        self.log.append({"at": self.clock().isoformat(), "kind": "executor", "action": action, **extra})

    def _verify(self, decision: dict) -> None:
        body = {k: v for k, v in decision.items() if k != "sig"}
        good = hmac.new(self._key, _canon(body).encode(), hashlib.sha256).hexdigest()
        if not isinstance(decision.get("sig"), str) or not hmac.compare_digest(decision["sig"], good):
            self._record("decision_refused_bad_signature", request=decision.get("request_id"))
            raise ExecError("the gateway's signature does not match")
        from datetime import datetime
        if datetime.fromisoformat(decision["expires"]) <= self.clock():
            self._record("decision_refused_expired", request=decision["request_id"])
            raise ExecError("the decision has expired")

    def prepare(self, decision: dict) -> dict:
        """Check the decision and take a short-lived credential. Raises ExecError if anything is wrong."""
        self._verify(decision)
        if decision["request_id"] in self.done:
            self._record("duplicate_ignored", request=decision["request_id"])
            return {"duplicate": True, "decision": decision}
        try:
            lid, token = self.vault.lease_api_token(EXECUTOR, decision["request_id"], decision["agent"])
        except VaultError as e:
            raise ExecError(str(e))
        return {"decision": decision, "lease": lid, "token": token}

    def call(self, prepared: dict) -> dict:
        d = prepared["decision"]
        if prepared.get("duplicate"):
            return {"outcome": "duplicate_ignored", "request_id": d["request_id"]}
        tok = prepared["token"]
        try:
            if d["action"] == "create_user":
                res = self.api.create_user(d["target"], token=tok)
                logged = {"user_id": res["id"]}
            elif d["action"] == "disable_user":
                res = self.api.set_active(d["target"]["staff_id"], False, token=tok)
                logged = {"user_id": d["target"]["staff_id"]}
            elif d["action"] == "read_user":
                res = self.api.get_user(d["target"]["staff_id"], token=tok)
                logged = {"user_id": d["target"]["staff_id"]}
            else:
                raise ExecError("no such action")
        except ApiError as e:
            self._record("api_refused", request=d["request_id"], status=e.status)
            self.vault.revoke_lease(prepared["lease"], why="api_refused")
            return {"outcome": "api_refused", "request_id": d["request_id"], "status": e.status}
        self.vault.revoke_lease(prepared["lease"], why="checked_in")
        self.done[d["request_id"]] = {"at": self.clock().isoformat()}
        self._record("executed", request=d["request_id"], requested=d["action"], agent=d["agent"],
                     approved_by=d["approved_by"], lease=prepared["lease"], **logged)
        reply = {"outcome": "executed", "request_id": d["request_id"], **logged}
        if d["action"] == "read_user":
            reply["user"] = {"id": res["id"], "team": res["team"], "active": res["active"]}
        return reply

    def execute(self, decision: dict) -> dict:
        try:
            return self.call(self.prepare(decision))
        except ExecError as e:
            return {"outcome": "refused", "reason": str(e)}


def wire(world) -> "Plumbing":
    return Plumbing(world)


class Plumbing:
    """Everything round six needs, wired onto a fresh Kaveri Finance world."""

    def __init__(self, world):
        self.w = world
        self.api = IdmApi(world.staff, world.clock)
        self.vault = Vault(world.log, world.clock, self.api)
        self.gateway = ActionGateway(world.identity, self.api, world.log, world.clock)
        self.executor = Executor(self.gateway, self.vault, self.api, world.log, world.clock)
        self.vault.allow(EXECUTOR, API_TOKEN_PATH, API_PASSWORD_PATH)       # only the executor can read
        world.identity.people_scopes = {}

    def agent(self, agent_id: str, sponsor: str, scopes: set[str]) -> str:
        """Register an agent and give it a short-lived token made for the gateway."""
        self.w.identity.register_agent(agent_id, sponsor, {"idm.gateway"} | scopes)
        return self.w.identity.issue_token(agent_id, minutes=15, audience=GATEWAY_AUDIENCE)

    def kill(self, agent_id: str, by: str) -> dict:
        self.w.identity.kill(agent_id, by)
        c = self.gateway.on_kill(agent_id)
        c["leases_revoked"] = self.vault.revoke_for_agent(agent_id)
        return c
