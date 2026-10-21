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

    def _record(self, action: str, **extra):
        self.log.append({"at": self.clock().isoformat(), "kind": "identity", "action": action, **extra})

    # Registration and lifecycle

    def register_agent(self, agent_id: str, sponsor: str | None, scopes: set[str]) -> Agent:
        if not sponsor or sponsor not in self.staff or not self.staff[sponsor]["active"]:
            raise IdentityError("An agent needs a named, active human sponsor.")
        agent = Agent(agent_id, sponsor, set(scopes))
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

    def kill(self, agent_id: str, by: str) -> None:
        a = self.agents[agent_id]
        a.status = "killed"
        self.revoked_before[agent_id] = self.clock() + timedelta(microseconds=1)
        self._record("agent_killed", agent=agent_id, by=by)

    def orphans(self) -> list[str]:
        now = self.clock()
        return sorted(a.id for a in self.agents.values()
                      if a.status == "active" and (a.last_seen is None or now - a.last_seen > timedelta(days=ORPHAN_DAYS)))

    # Tokens

    def authenticate_static_key(self, agent_id: str, api_key: str):
        self._record("static_key_refused", agent=agent_id)
        raise IdentityError("Static API keys are not accepted. Ask for a short-lived token.")

    def issue_token(self, agent_id: str, minutes: int = MAX_TOKEN_MINUTES, on_behalf_of: str | None = None,
                    scopes: set[str] | None = None) -> str:
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
        body = _b64(json.dumps(claims, sort_keys=True).encode())
        sig = _b64(hmac.new(self._signing_key, body.encode(), hashlib.sha256).digest())
        self._record("token_issued", agent=agent_id, jti=claims["jti"], obo=on_behalf_of, minutes=minutes)
        return f"{body}.{sig}"

    def verify(self, token: str, needed_scope: str, fingerprint: str = "default") -> dict:
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
        if needed_scope not in claims["scp"]:
            self._record("scope_denied", agent=a.id, scope=needed_scope)
            raise IdentityError(f"Scope {needed_scope} not granted.")
        users = self.token_use.setdefault(claims["jti"], set())
        users.add(fingerprint)
        if len(users) > 1:
            self._record("shared_token_detected", agent=a.id, jti=claims["jti"], fingerprints=sorted(users))
        a.last_seen = now
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

    def request_privilege(self, agent_id: str, action: str, approver: str, minutes: int = 30) -> dict:
        a = self.agents[agent_id]
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
