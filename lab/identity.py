from __future__ import annotations
"""Agent identity and access: every AI agent gets its own identity, a named
human sponsor, a fixed set of scopes and short-lived signed tokens. Agents
acting for a person never get more than that person has. Privileged actions
need a just-in-time grant from someone else, with an expiry and a session
record. A kill switch revokes everything an agent holds."""
import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .hashlog import HashLog

MAX_TOKEN_MINUTES = 15
ORPHAN_DAYS = 30
REVIEW_DAYS = 30             # an agent nobody has reviewed for this long is switched off
MFA_FRESH_MINUTES = 10       # an approver's last sign-in check must be this recent
TOXIC = [({"hr.read"}, {"email.send"}), ({"customers.export"}, {"email.send"}), ({"files.read.all"}, {"web.post"})]


class IdentityError(Exception):
    pass


@dataclass
class Agent:
    id: str
    sponsor: str
    scopes: set[str]
    status: str = "active"          # active, disabled, killed
    key: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    last_seen: datetime | None = None
    created: datetime | None = None
    reviewed: datetime | None = None


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class IdentityService:
    def __init__(self, staff: list[dict], log: HashLog, clock):
        self.staff = {s["id"]: s for s in staff}
        self.people_scopes: dict[str, set[str]] = {}
        self.agents: dict[str, Agent] = {}
        self.log = log
        self.clock = clock
        self._signing_key = secrets.token_bytes(32)
        self.revoked_before: dict[str, datetime] = {}       # agent -> tokens issued before this are dead
        self.token_use: dict[str, set[str]] = {}            # token id -> fingerprints that used it
        self.grants: list[dict] = []
        self.sessions: list[dict] = []
        self.scope_use: dict[str, dict[str, int]] = {}      # agent -> scope -> times used

    def _record(self, action: str, **extra):
        self.log.append({"at": self.clock().isoformat(), "kind": "identity", "action": action, **extra})

    # Registration and lifecycle

    def register_agent(self, agent_id: str, sponsor: str | None, scopes: set[str]) -> Agent:
        if not sponsor or sponsor not in self.staff or not self.staff[sponsor]["active"]:
            raise IdentityError("An agent needs a named, active human sponsor.")
        for a, b in TOXIC:
            if a <= set(scopes) and b <= set(scopes):
                self._record("toxic_combination_refused", agent=agent_id, scopes=sorted(scopes))
                raise IdentityError(f"Toxic combination: {sorted(a)} with {sorted(b)} in one agent.")
        agent = Agent(agent_id, sponsor, set(scopes), created=self.clock(), reviewed=self.clock())
        self.agents[agent_id] = agent
        self._record("agent_registered", agent=agent_id, sponsor=sponsor, scopes=sorted(scopes))
        return agent

    def sponsor_left(self, staff_id: str) -> list[str]:
        self.staff[staff_id]["active"] = False
        disabled = []
        for a in self.agents.values():
            if a.sponsor == staff_id and a.status == "active":
                a.status = "disabled"
                self.revoked_before[a.id] = self.clock()
                disabled.append(a.id)
                self._record("agent_disabled_sponsor_left", agent=a.id, sponsor=staff_id)
        return disabled

    def person_left(self, staff_id: str) -> list[str]:
        """Someone left: their sponsored agents stop, and tokens issued on their behalf stop too."""
        return self.sponsor_left(staff_id)

    def sponsor_moved(self, staff_id: str, new_team: str) -> list[str]:
        """A sponsor changes team: their agents are paused until a new approver re-confirms them."""
        self.staff[staff_id]["team"] = new_team
        held = []
        for a in self.agents.values():
            if a.sponsor == staff_id and a.status == "active":
                a.status = "review"
                self.revoked_before[a.id] = self.clock()
                held.append(a.id)
                self._record("agent_held_sponsor_moved", agent=a.id, sponsor=staff_id, new_team=new_team)
        return held

    def recertify_agent(self, agent_id: str, reviewer: str, keep_scopes: set[str] | None = None) -> Agent:
        a = self.agents[agent_id]
        who = self.staff.get(reviewer, {})
        if not who.get("active") or who.get("role") != "approver" or reviewer == a.sponsor:
            raise IdentityError("Only an active approver, who is not the sponsor, can re-confirm an agent.")
        if keep_scopes is not None:
            a.scopes &= set(keep_scopes)
        a.status = "active"
        a.reviewed = self.clock()
        self._record("agent_recertified", agent=a.id, reviewer=reviewer, scopes=sorted(a.scopes))
        return a

    def access_review(self) -> dict:
        """Scopes an agent holds but has never used, and agents nobody has reviewed in REVIEW_DAYS days (switched off)."""
        now = self.clock()
        unused, lapsed = {}, []
        for a in self.agents.values():
            used = set(self.scope_use.get(a.id, {}))
            if a.scopes - used:
                unused[a.id] = sorted(a.scopes - used)
            if a.status == "active" and now - (a.reviewed or a.created or now) > timedelta(days=REVIEW_DAYS):
                a.status = "disabled"
                self.revoked_before[a.id] = now
                lapsed.append(a.id)
                self._record("agent_lapsed_unreviewed", agent=a.id)
        return {"unused_scopes": unused, "lapsed": sorted(lapsed)}

    def kill(self, agent_id: str, by: str) -> None:
        a = self.agents[agent_id]
        a.status = "killed"
        self.revoked_before[agent_id] = self.clock() + timedelta(microseconds=1)
        self._record("agent_killed", agent=agent_id, by=by)

    def orphans(self) -> list[str]:
        now = self.clock()
        return sorted(a.id for a in self.agents.values()
                      if a.status == "active" and now - (a.last_seen or a.created or now) > timedelta(days=ORPHAN_DAYS))

    # Tokens

    def authenticate_static_key(self, agent_id: str, api_key: str):
        self._record("static_key_refused", agent=agent_id)
        raise IdentityError("Static API keys are not accepted. Ask for a short-lived token.")

    def issue_token(self, agent_id: str, minutes: int = MAX_TOKEN_MINUTES, on_behalf_of: str | None = None,
                    scopes: set[str] | None = None, audience: str | None = None) -> str:
        a = self.agents.get(agent_id)
        if a is None or a.status != "active":
            raise IdentityError("Agent is not active.")
        if minutes > MAX_TOKEN_MINUTES:
            raise IdentityError(f"Tokens last at most {MAX_TOKEN_MINUTES} minutes.")
        granted = set(scopes) if scopes is not None else set(a.scopes)
        if not granted <= a.scopes:
            raise IdentityError("Asked for scopes the agent wasn't registered for.")
        if on_behalf_of is not None:
            person = self.people_scopes.get(on_behalf_of, set())
            if not granted <= person:
                raise IdentityError("An agent acting for a person can't have more than that person.")
        now = self.clock()
        claims = {"jti": secrets.token_hex(8), "sub": agent_id, "obo": on_behalf_of, "scp": sorted(granted),
                  "iat": now.timestamp(), "exp": (now + timedelta(minutes=minutes)).timestamp()}
        if audience is not None:
            claims["aud"] = audience
        body = _b64(json.dumps(claims, sort_keys=True).encode())
        sig = _b64(hmac.new(self._signing_key, body.encode(), hashlib.sha256).digest())
        self._record("token_issued", agent=agent_id, jti=claims["jti"], obo=on_behalf_of, minutes=minutes)
        return f"{body}.{sig}"

    def verify(self, token: str, needed_scope: str, fingerprint: str = "default", audience: str | None = None) -> dict:
        try:
            body, sig = token.split(".")
        except ValueError:
            raise IdentityError("Malformed token.")
        good = _b64(hmac.new(self._signing_key, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, good):
            raise IdentityError("Bad signature.")
        claims = json.loads(_unb64(body))
        now = self.clock()
        if now.timestamp() >= claims["exp"]:
            raise IdentityError("Token expired.")
        a = self.agents.get(claims["sub"])
        if a is None or a.status != "active":
            raise IdentityError("Agent is not active.")
        cut = self.revoked_before.get(a.id)
        if cut is not None and claims["iat"] <= cut.timestamp():
            raise IdentityError("Token revoked.")
        if audience is not None and claims.get("aud") is not None and claims["aud"] != audience:
            self._record("token_wrong_audience", agent=a.id, made_for=claims["aud"], shown_to=audience)
            raise IdentityError(f"Token was made for {claims['aud']}, not for {audience}.")
        obo = claims.get("obo")
        if obo is not None and not self.staff.get(obo, {}).get("active", True):
            self._record("token_refused_user_left", agent=a.id, obo=obo)
            raise IdentityError("The person this agent acts for is no longer active.")
        if needed_scope not in claims["scp"]:
            self._record("scope_denied", agent=a.id, scope=needed_scope)
            raise IdentityError(f"Scope {needed_scope} not granted.")
        users = self.token_use.setdefault(claims["jti"], set())
        users.add(fingerprint)
        if len(users) > 1:
            self._record("shared_token_detected", agent=a.id, jti=claims["jti"], fingerprints=sorted(users))
        a.last_seen = now
        use = self.scope_use.setdefault(a.id, {})
        use[needed_scope] = use.get(needed_scope, 0) + 1
        return claims

    def shared_tokens(self) -> list[str]:
        return sorted(j for j, fp in self.token_use.items() if len(fp) > 1)

    # Agent-to-agent messages

    def sign_message(self, agent_id: str, message: dict) -> dict:
        a = self.agents[agent_id]
        raw = json.dumps(message, sort_keys=True).encode()
        return {"from": agent_id, "message": message, "sig": hmac.new(a.key, raw, hashlib.sha256).hexdigest()}

    def accept_message(self, envelope: dict) -> dict:
        sender = self.agents.get(envelope.get("from", ""))
        if sender is None or sender.status != "active" or "sig" not in envelope:
            self._record("agent_message_rejected", sender=envelope.get("from"))
            raise IdentityError("Message has no valid sender identity.")
        raw = json.dumps(envelope["message"], sort_keys=True).encode()
        if not hmac.compare_digest(envelope["sig"], hmac.new(sender.key, raw, hashlib.sha256).hexdigest()):
            self._record("agent_message_rejected", sender=sender.id)
            raise IdentityError("Message signature doesn't match.")
        return envelope["message"]

    # Privileged access (PAM)

    def request_privilege(self, agent_id: str, action: str, approver: str, minutes: int = 30,
                          approver_mfa_minutes_ago: int | None = None) -> dict:
        a = self.agents[agent_id]
        if approver_mfa_minutes_ago is not None and approver_mfa_minutes_ago > MFA_FRESH_MINUTES:
            self._record("jit_refused_stale_signin", agent=agent_id, approver=approver, minutes_ago=approver_mfa_minutes_ago)
            raise IdentityError(f"The approver's last sign-in check was {approver_mfa_minutes_ago} minutes ago; it must be within {MFA_FRESH_MINUTES}.")
        if approver == a.sponsor:
            raise IdentityError("The agent's own sponsor can't approve its privileged access.")
        if self.staff.get(approver, {}).get("role") != "approver":
            raise IdentityError("Only an approver can grant privileged access.")
        grant = {"id": f"JIT-{len(self.grants) + 1:03d}", "agent": agent_id, "action": action, "approver": approver,
                 "expires": self.clock() + timedelta(minutes=minutes)}
        self.grants.append(grant)
        self._record("jit_granted", agent=agent_id, what=action, approver=approver, minutes=minutes)
        return grant

    def privileged(self, agent_id: str, action: str) -> dict:
        now = self.clock()
        for g in self.grants:
            if g["agent"] == agent_id and g["action"] == action and g["expires"] > now:
                session = {"grant": g["id"], "agent": agent_id, "action": action, "at": now.isoformat(), "recorded": True}
                self.sessions.append(session)
                self._record("privileged_session", agent=agent_id, what=action, grant=g["id"])
                return session
        self._record("privileged_denied", agent=agent_id, what=action)
        raise IdentityError("No live just-in-time grant for this action.")


def timed(fn) -> float:
    """Milliseconds a call takes."""
    start = time.perf_counter()
    fn()
    return (time.perf_counter() - start) * 1000
