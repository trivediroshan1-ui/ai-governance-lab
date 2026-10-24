from __future__ import annotations
"""Round eleven: small models for delegation chains, public-key signing, key rotation,
merged directories, replayed messages and PAN masking (cases D1 to D12).
Written for this lab. Ed25519 comes from the 'cryptography' package; everything else is plain Python.
No real identity provider, tenant or AI model is involved."""
import json
import re
import secrets
from datetime import timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .hashlog import HashLog


class DelegationError(Exception):
    pass


class Delegation:
    """Agents hand work to other agents. Each live token records who it came from."""

    def __init__(self, clock, registered: dict[str, set[str]], narrow=True, max_depth=None, chain_log=True, cascade=True):
        self.clock, self.registered = clock, registered
        self.narrow, self.max_depth, self.chain_log, self.cascade = narrow, max_depth, chain_log, cascade
        self.tokens: dict[str, dict] = {}
        self.revoked: set[str] = set()
        self.log = HashLog()

    def start(self, person: str, agent: str, scopes: set[str]) -> str:
        jti = secrets.token_hex(4)
        self.tokens[jti] = {"jti": jti, "agent": agent, "scp": set(scopes) & self.registered[agent], "origin": person, "chain": [agent], "parent": None, "depth": 0}
        return jti

    def hand_on(self, jti: str, to_agent: str, task_scopes: set[str]) -> str:
        p = self.tokens[jti]
        depth = p["depth"] + 1
        if self.max_depth is not None and depth > self.max_depth:
            raise DelegationError(f"too many hops ({depth}); the limit is {self.max_depth}")
        scopes = set(p["scp"])
        if self.narrow:
            scopes = scopes & self.registered[to_agent] & set(task_scopes)
        child = secrets.token_hex(4)
        self.tokens[child] = {"jti": child, "agent": to_agent, "scp": scopes, "origin": p["origin"], "chain": p["chain"] + [to_agent], "parent": jti, "depth": depth}
        return child

    def revoke_person(self, person: str) -> None:
        for t in self.tokens.values():
            if t["parent"] is None and t["origin"] == person:
                self.revoked.add(t["jti"])

    def _alive(self, jti: str) -> bool:
        t = self.tokens[jti]
        if jti in self.revoked:
            return False
        if self.cascade and t["parent"] is not None:
            return self._alive(t["parent"])
        return True

    def act(self, jti: str, scope: str, what: str) -> bool:
        t = self.tokens[jti]
        if not self._alive(jti) or scope not in t["scp"]:
            return False
        line = {"at": self.clock().isoformat(), "agent": t["agent"], "action": what}
        if self.chain_log:
            line.update({"origin": t["origin"], "chain": t["chain"]})
        self.log.append(line)
        return True


# ---- keys

def new_key():
    return Ed25519PrivateKey.generate()


def pub_hex(priv) -> str:
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def verify_sig(pub: str, sig: str, data: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(bytes.fromhex(sig), data)
        return True
    except (InvalidSignature, ValueError):
        return False


class ProofResource:
    """Checks that a request is signed with the key the token is tied to."""

    def __init__(self, clock, nonce_check: bool):
        self.clock, self.nonce_check = clock, nonce_check
        self.seen: set[str] = set()

    def call(self, token_pub: str, body: str, nonce: str, ts: float, sig: str) -> bool:
        if not verify_sig(token_pub, sig, f"{body}|{nonce}|{ts}".encode()):
            return False
        if self.nonce_check:
            if abs(self.clock().timestamp() - ts) > 60 or nonce in self.seen:
                return False
            self.seen.add(nonce)
        return True


def canon(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


class Executor:
    """Accepts a signed decision. mode 'shared' = same secret on both sides (HMAC);
    'public' = checks an Ed25519 signature with the gateway's public key."""

    HIGH_RISK = {"delete_user"}

    def __init__(self, clock, mode: str, gateway_pub: str | None = None, shared: bytes | None = None, approver_pub: str | None = None,
                 require_cosign: bool = False, keys: dict | None = None, use_kid: bool = False):
        self.clock, self.mode, self.gateway_pub, self.shared = clock, mode, gateway_pub, shared
        self.approver_pub, self.require_cosign = approver_pub, require_cosign
        self.keys = keys or {}                 # kid -> {"pub":..., "retired": datetime | None}
        self.use_kid = use_kid

    def accepts(self, decision: dict, sig: str, cosig: str | None = None) -> bool:
        data = canon(decision)
        if self.mode == "shared":
            import hashlib, hmac
            ok = hmac.compare_digest(sig, hmac.new(self.shared, data, hashlib.sha256).hexdigest())
        elif self.keys:
            if self.use_kid:
                k = self.keys.get(decision.get("kid"))
                if k is None or (k["retired"] is not None and self.clock() > k["retired"]):
                    return False
                ok = verify_sig(k["pub"], sig, data)
            else:
                ok = any(verify_sig(k["pub"], sig, data) for k in self.keys.values())
        else:
            ok = verify_sig(self.gateway_pub, sig, data)
        if not ok:
            return False
        if self.require_cosign and decision.get("action") in self.HIGH_RISK:
            return bool(cosig) and verify_sig(self.approver_pub, cosig, data)
        return True


class MergedDirectory:
    def __init__(self, namespace: bool):
        self.namespace, self.access = namespace, {}

    def add(self, company: str, staff_id: str, entitlements: set[str]):
        k = f"{company}:{staff_id}" if self.namespace else staff_id
        self.access[k] = self.access.get(k, set()) | set(entitlements)

    def of(self, company: str, staff_id: str) -> set[str]:
        return self.access.get(f"{company}:{staff_id}" if self.namespace else staff_id, set())


class AgentBus:
    """Agent-to-agent messages over the identity service's signing. 'nonce' adds a one-time number and an expiry."""

    def __init__(self, identity, clock, nonce: bool):
        self.identity, self.clock, self.nonce = identity, clock, nonce
        self.seen: set[str] = set()

    def send(self, sender: str, message: dict) -> dict:
        if self.nonce:
            message = {**message, "nonce": secrets.token_hex(6), "exp": (self.clock() + timedelta(minutes=5)).timestamp()}
        return self.identity.sign_message(sender, message)

    def receive(self, envelope: dict) -> dict | None:
        try:
            m = self.identity.accept_message(envelope)
        except Exception:
            return None
        if self.nonce:
            if m["nonce"] in self.seen or self.clock().timestamp() > m["exp"]:
                return None
            self.seen.add(m["nonce"])
        return m


PAN_STRICT = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
PAN_LOOSE = re.compile(r"\b[A-Za-z]{5} ?\d{4} ?[A-Za-z]\b")


class PanIndex:
    def __init__(self, docs: list[str], normalise: bool):
        rx = PAN_LOOSE if normalise else PAN_STRICT
        self.chunks = [rx.sub("[PAN]", d) for d in docs]

    def finds(self, number: str) -> bool:
        return any(number.lower() in c.lower() for c in self.chunks)
