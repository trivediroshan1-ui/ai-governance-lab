from __future__ import annotations
"""Round ten: small models for credential and identity edge cases (cases C1 to C12).
Everything here is a stand-in written for the lab. The key proof uses a shared secret
(real systems use a public key, as in DPoP or mutual TLS); the 'identity provider' and
the 'app' are plain classes. Nothing talks to a real tenant."""
import hashlib
import hmac
import json
import secrets
from datetime import timedelta

from .hashlog import HashLog


def _b(raw: bytes) -> str:
    return raw.hex()


class Idp:
    """Issues signed session tokens that an app can check offline, and signs revoke signals."""

    def __init__(self, clock):
        self.clock = clock
        self._key = secrets.token_bytes(32)
        self.client_keys = {}          # jti -> client key (lab stand-in for a public key on file)

    def issue(self, person: str, minutes: int = 60, client_key: bytes | None = None) -> str:
        now = self.clock()
        claims = {"jti": secrets.token_hex(6), "sub": person, "iat": now.timestamp(),
                  "exp": (now + timedelta(minutes=minutes)).timestamp(), "bound": client_key is not None}
        if client_key is not None:
            self.client_keys[claims["jti"]] = client_key
        body = json.dumps(claims, sort_keys=True)
        return body.encode().hex() + "." + hmac.new(self._key, body.encode(), hashlib.sha256).hexdigest()

    def signal(self, person: str, state: str, at=None, sign: bool = True) -> dict:
        ev = {"sub": person, "state": state, "at": (at or self.clock()).timestamp()}
        raw = json.dumps(ev, sort_keys=True).encode()
        return {"event": ev, "sig": hmac.new(self._key, raw, hashlib.sha256).hexdigest() if sign else None}

    def check_sig(self, body: str, sig: str) -> bool:
        return hmac.compare_digest(sig, hmac.new(self._key, body.encode(), hashlib.sha256).hexdigest())

    def check_event(self, env: dict) -> bool:
        raw = json.dumps(env["event"], sort_keys=True).encode()
        return bool(env.get("sig")) and hmac.compare_digest(env["sig"], hmac.new(self._key, raw, hashlib.sha256).hexdigest())


def proof(client_key: bytes, token: str, body: str) -> str:
    return hmac.new(client_key, (token + body).encode(), hashlib.sha256).hexdigest()


class App:
    """A resource server that checks tokens on its own, without calling the identity provider."""

    def __init__(self, idp: Idp, clock, require_proof: bool = False, signals: str = "signed",
                 ordering: str = "time", slow_by_minutes: int = 0, drift_limit_minutes: int | None = None):
        self.idp, self.clock = idp, clock
        self.require_proof = require_proof
        self.signals = signals                      # "none", "unsigned_ok" or "signed"
        self.ordering = ordering                    # "time" or "arrival"
        self.slow = timedelta(minutes=slow_by_minutes)
        self.drift_limit = drift_limit_minutes
        self.state: dict[str, tuple[float, str]] = {}

    def now(self):
        return self.clock() - self.slow

    def receive(self, env: dict) -> str:
        if self.signals == "none":
            return "ignored"
        if self.signals == "signed" and not self.idp.check_event(env):
            return "refused_unsigned"
        ev = env["event"]
        old = self.state.get(ev["sub"])
        if self.ordering == "time" and old and ev["at"] < old[0]:
            return "ignored_older"
        self.state[ev["sub"]] = (ev["at"], ev["state"])
        return "applied"

    def call(self, token: str, body: str = "", prf: str | None = None) -> tuple[bool, str]:
        try:
            raw, sig = token.split(".")
            text = bytes.fromhex(raw).decode()
        except ValueError:
            return False, "malformed"
        if not self.idp.check_sig(text, sig):
            return False, "bad signature"
        claims = json.loads(text)
        if self.drift_limit is not None and abs((self.clock() - self.now()).total_seconds()) > self.drift_limit * 60:
            return False, "clock too far from the reference, will not decide"
        if self.now().timestamp() >= claims["exp"]:
            return False, "expired"
        st = self.state.get(claims["sub"])
        if st and st[1] == "revoked":
            return False, "revoked by signal"
        if self.require_proof and claims["bound"]:
            key = self.idp.client_keys.get(claims["jti"])
            if prf is None or key is None or not hmac.compare_digest(prf, proof(key, token, body)):
                return False, "no valid proof of the key"
        elif self.require_proof and not claims["bound"]:
            return False, "token not tied to a key"
        return True, "ok"


class Directory:
    """A SCIM-like user store. PUT replaces the record; fields left out fall back to defaults."""
    DEFAULTS = {"active": True}

    def __init__(self):
        self.users = {}

    def create(self, uid: str, rec: dict):
        self.users[uid] = {**self.DEFAULTS, **rec}

    def put(self, uid: str, rec: dict):
        self.users[uid] = {**self.DEFAULTS, **rec}      # whole record replaced

    def patch(self, uid: str, changes: dict):
        self.users[uid].update(changes)

    def sync_title(self, uid: str, title: str, mode: str):
        if mode == "patch":
            self.patch(uid, {"title": title})
        else:
            self.put(uid, {"userName": self.users[uid]["userName"], "title": title})


BASELINE = {"support": {"support-view"}, "collections": {"support-view", "collections-write", "payments-view"}}


class Accounts:
    """Joiners, rehires, name changes, contractors."""

    def __init__(self, clock):
        self.clock = clock
        self.by_key = {}
        self.archive = {}
        self.contractors = {}

    # rehire
    def leave(self, sid: str):
        self.archive[sid] = self.by_key.pop(sid)

    def rehire(self, sid: str, job: str, mode: str) -> dict:
        if mode == "restore":
            acct = self.archive.pop(sid)
            acct["active"] = True
        else:
            self.archive.pop(sid, None)
            acct = {"id": sid, "name": "x", "job": job, "ent": set(BASELINE[job]), "active": True}
        self.by_key[sid] = acct
        return acct

    # name change
    def sync_person(self, rec: dict, match: str):
        k = rec["name"] if match == "name" else rec["id"]
        found = [a for a in self.by_key.values() if (a["name"] if match == "name" else a["id"]) == k]
        if found:
            found[0].update({"name": rec["name"], "email": rec["email"]})
            return
        new = {"id": rec["id"], "name": rec["name"], "email": rec["email"], "active": True, "ent": set(BASELINE["support"])}
        self.by_key[f"{rec['id']}-{len(self.by_key)}"] = new

    # contractor
    def add_contractor(self, cid: str, agency: str, ends_in_days: int | None, require_end: bool, max_days: int = 90):
        now = self.clock()
        ends = None if ends_in_days is None else now + timedelta(days=ends_in_days)
        if require_end:
            cap = now + timedelta(days=max_days)
            ends = cap if ends is None or ends > cap else ends
        self.contractors[cid] = {"agency": agency, "ends": ends, "active": True}

    def sweep(self):
        for c in self.contractors.values():
            if c["ends"] is not None and self.clock() >= c["ends"]:
                c["active"] = False


class BreakGlass:
    def __init__(self, alert: bool, rotate: bool):
        self.alert, self.rotate = alert, rotate
        self.password = "bg-pass-1"
        self.alerts = []
        self.sessions = []

    def use(self, who: str, password: str) -> bool:
        if password != self.password:
            return False
        self.sessions.append(who)
        if self.alert:
            self.alerts.append(f"break-glass used by {who}")
        return True

    def check_in(self):
        if self.rotate:
            self.password = "bg-pass-" + secrets.token_hex(4)


class ErasableLog:
    """Audit lines hold either a person's name or a pseudonym that points into a separate store."""

    def __init__(self, pseudonymise: bool):
        self.log = HashLog()
        self.pseudo = pseudonymise
        self.names = {}

    def write(self, name: str, action: str, at: str):
        if self.pseudo:
            pid = "P-" + hashlib.sha256(name.encode() + b"lab-salt").hexdigest()[:10]
            self.names[pid] = name
            self.log.append({"at": at, "who": pid, "action": action})
        else:
            self.log.append({"at": at, "who": name, "action": action})

    def erase(self, name: str):
        if self.pseudo:
            for k in [k for k, v in self.names.items() if v == name]:
                del self.names[k]
        else:
            for line in self.log.lines:
                if line["body"].get("who") == name:
                    line["body"]["who"] = "[erased]"

    def name_remains(self, name: str) -> bool:
        return name in json.dumps(self.log.lines) or name in self.names.values()
