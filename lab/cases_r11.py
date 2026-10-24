from __future__ import annotations
"""Round eleven: delegation, keys and organisations (cases D1 to D12).
The expected results were committed in cases/round-11.json before this file existed.
Each function takes a detector (not used) and returns (outcome, details)."""
import random

from . import ids
from .delegation import (AgentBus, Delegation, DelegationError, Executor, MergedDirectory, PanIndex, ProofResource,
                         canon, new_key, pub_hex)
from .identity import IdentityError
from .world import World

CASES = {}
REG = {"A": {"read_customer", "write_customer"}, "B": {"read_customer", "send_report"}, "C": {"read_customer"}, "D": {"read_customer"}, "E": {"read_customer"}}


def case(cid):
    def wrap(fn):
        CASES[cid] = fn
        return fn
    return wrap


@case("D1")
def d1(det):
    out = {}
    for name, narrow in (("inherits_all", False), ("narrowed", True)):
        w = World(); d = Delegation(w.clock, REG, narrow=narrow)
        a = d.start("S002", "A", {"read_customer", "write_customer"})
        b = d.hand_on(a, "B", {"read_customer"})
        out[name] = d.act(b, "write_customer", "B writes a customer record")
    ok = out["inherits_all"] and not out["narrowed"]
    return ("inherits_all_narrowed_holds" if ok else "other"), {"B_can_write_when_it_inherits_all": out["inherits_all"], "B_can_write_when_narrowed": out["narrowed"]}


@case("D2")
def d2(det):
    out = {}
    for name, lim in (("no_limit", None), ("limit_two", 2)):
        w = World(); d = Delegation(w.clock, REG, max_depth=lim)
        t = d.start("S002", "A", {"read_customer"}); hops = 0
        try:
            for nxt in ("B", "C", "D", "E"):
                t = d.hand_on(t, nxt, {"read_customer"}); hops += 1
        except DelegationError:
            pass
        out[name] = hops
    ok = out["no_limit"] == 4 and out["limit_two"] == 2
    return ("unlimited_chain_depth_limit_holds" if ok else "other"), {"hops_reached_with_no_limit": out["no_limit"], "hops_reached_with_limit_two": out["limit_two"]}


@case("D3")
def d3(det):
    out = {}
    for name, cl in (("last_hop_only", False), ("full_chain", True)):
        w = World(); d = Delegation(w.clock, REG, chain_log=cl)
        t = d.start("S002", "A", {"read_customer"})
        for nxt in ("B", "C", "D"):
            t = d.hand_on(t, nxt, {"read_customer"})
        d.act(t, "read_customer", "read record C0042")
        line = d.log.events()[-1]
        out[name] = {"names_the_person": line.get("origin") == "S002", "agents_listed": len(line.get("chain", [line["agent"]]))}
    ok = not out["last_hop_only"]["names_the_person"] and out["full_chain"]["names_the_person"] and out["full_chain"]["agents_listed"] == 4
    return ("last_hop_only_chain_names_origin" if ok else "other"), out


@case("D4")
def d4(det):
    out = {}
    for name, cas in (("no_cascade", False), ("cascade", True)):
        w = World(); d = Delegation(w.clock, REG, cascade=cas)
        t = d.start("S002", "A", {"read_customer"})
        for nxt in ("B", "C"):
            t = d.hand_on(t, nxt, {"read_customer"})
        d.revoke_person("S002")
        out[name] = d.act(t, "read_customer", "read after the person left")
    ok = out["no_cascade"] and not out["cascade"]
    return ("child_survives_parent_revoke_cascade_holds" if ok else "other"), {"last_agent_still_works_without_cascade": out["no_cascade"], "last_agent_still_works_with_cascade": out["cascade"]}


@case("D5")
def d5(det):
    out = {}
    for name, nc in (("no_nonce", False), ("nonce", True)):
        w = World(); key = new_key(); res = ProofResource(w.clock, nc)
        body, nonce, ts = "pay 100", "n-0001", w.clock().timestamp()
        sig = key.sign(f"{body}|{nonce}|{ts}".encode()).hex()
        first = res.call(pub_hex(key), body, nonce, ts, sig)
        w.clock.advance(seconds=20)
        replay = res.call(pub_hex(key), body, nonce, ts, sig)
        thief = res.call(pub_hex(key), body, "n-0002", w.clock().timestamp(), new_key().sign(b"x").hex())
        out[name] = {"owner": first, "replay": replay, "thief_without_key": thief}
    ok = out["no_nonce"]["replay"] and not out["nonce"]["replay"] and out["nonce"]["owner"] and not out["nonce"]["thief_without_key"] and not out["no_nonce"]["thief_without_key"]
    return ("replayed_proof_accepted_nonce_holds" if ok else "other"), out


@case("D6")
def d6(det):
    w = World(); gw = new_key(); shared = b"shared-secret-both-sides-hold"
    forged = {"request_id": "R-x", "action": "create_user", "target": "evil", "agent": "A"}
    import hashlib, hmac
    forged_sig_shared = hmac.new(shared, canon(forged), hashlib.sha256).hexdigest()      # a compromised executor holds the secret
    shared_ok = Executor(w.clock, "shared", shared=shared).accepts(forged, forged_sig_shared)
    attacker_sig = new_key().sign(canon(forged)).hex()                                   # with only the public half it can sign only with its own key
    public_ok = Executor(w.clock, "public", gateway_pub=pub_hex(gw)).accepts(forged, attacker_sig)
    real = {"request_id": "R-1", "action": "create_user", "target": "meera", "agent": "A"}
    real_ok = Executor(w.clock, "public", gateway_pub=pub_hex(gw)).accepts(real, gw.sign(canon(real)).hex())
    ok = shared_ok and not public_ok and real_ok
    return ("shared_key_executor_forges_public_key_holds" if ok else "other"), {"forged_accepted_with_shared_secret": shared_ok, "forged_accepted_with_public_key": public_ok, "real_decision_accepted": real_ok}


@case("D7")
def d7(det):
    w = World(); gw, appr = new_key(), new_key()
    dec = {"request_id": "R-9", "action": "delete_user", "target": "S010", "agent": "A"}
    sig = gw.sign(canon(dec)).hex()                                   # a compromised gateway can sign anything
    alone = Executor(w.clock, "public", gateway_pub=pub_hex(gw)).accepts(dec, sig)
    ex = Executor(w.clock, "public", gateway_pub=pub_hex(gw), approver_pub=pub_hex(appr), require_cosign=True)
    no_cosign = ex.accepts(dec, sig)
    with_cosign = ex.accepts(dec, sig, appr.sign(canon(dec)).hex())
    ok = alone and not no_cosign and with_cosign
    return ("forged_decision_accepted_cosign_holds" if ok else "other"), {"accepted_on_gateway_signature_alone": alone, "accepted_with_cosign_required_but_missing": no_cosign, "accepted_with_a_real_cosign": with_cosign}


@case("D8")
def d8(det):
    out = {}
    for name, kid in (("no_kid_no_window", False), ("kid_and_window", True)):
        w = World(); old, new = new_key(), new_key()
        keys = {"k1": {"pub": pub_hex(old), "retired": w.clock() + __import__("datetime").timedelta(days=1)}, "k2": {"pub": pub_hex(new), "retired": None}}
        w.clock.advance(days=3)                                       # k1 was retired two days ago
        dec = {"request_id": "R-3", "action": "create_user", "target": "x", "agent": "A", "kid": "k1"}
        out[name] = Executor(w.clock, "public", keys=keys, use_kid=kid).accepts(dec, old.sign(canon(dec)).hex())
    ok = out["no_kid_no_window"] and not out["kid_and_window"]
    return ("old_key_accepted_window_holds" if ok else "other"), {"old_key_accepted_without_window": out["no_kid_no_window"], "old_key_accepted_with_window": out["kid_and_window"]}


@case("D9")
def d9(det):
    out = {}
    for name, ns in (("raw_ids", False), ("prefixed", True)):
        m = MergedDirectory(ns)
        m.add("Kaveri", "S001", {"payments-approve", "hr-read"})
        m.add("Nilgiri", "S001", {"support-view"})
        out[name] = sorted(m.of("Nilgiri", "S001"))
    ok = "payments-approve" in out["raw_ids"] and out["prefixed"] == ["support-view"]
    return ("collision_grants_other_access_namespace_holds" if ok else "other"), {"nilgiri_S001_has_with_raw_ids": out["raw_ids"], "nilgiri_S001_has_with_prefix": out["prefixed"]}


@case("D10")
def d10(det):
    out = {}
    for name, nc in (("no_nonce", False), ("nonce_and_expiry", True)):
        w = World()
        w.identity.register_agent("AG1", "S002", {"read_customer"}); w.identity.register_agent("AG2", "S002", {"read_customer"})
        bus = AgentBus(w.identity, w.clock, nc)
        env = bus.send("AG1", {"task": "export report 7"})
        first = bus.receive(env) is not None
        w.clock.advance(hours=1)
        again = bus.receive(env) is not None
        out[name] = {"first": first, "replayed_an_hour_later": again}
    ok = out["no_nonce"]["replayed_an_hour_later"] and not out["nonce_and_expiry"]["replayed_an_hour_later"] and out["nonce_and_expiry"]["first"]
    return ("replayed_message_accepted_nonce_holds" if ok else "other"), out


@case("D11")
def d11(det):
    pans = [ids.make_pan(random.Random(n)) for n in (11, 12, 13)]       # a different number for each way of writing it
    variants = {"capitals": pans[0], "lower_case": pans[1].lower(), "with_a_space": pans[2][:5] + " " + pans[2][5:]}
    docs = [f"Customer note: PAN {v} on file." for v in variants.values()]
    out = {}
    for name, norm in (("capitals_only_mask", False), ("normalising_mask", True)):
        ix = PanIndex(docs, norm)
        out[name] = {k: ix.finds(v) for k, v in variants.items()}
    ok = out["capitals_only_mask"] == {"capitals": False, "lower_case": True, "with_a_space": True} and not any(out["normalising_mask"].values())
    return ("lowercase_pan_found_normalised_masks" if ok else "other"), {"searchable_after_capitals_only_mask": out["capitals_only_mask"], "searchable_after_normalising_mask": out["normalising_mask"]}


@case("D12")
def d12(det):
    w = World(); ident = w.identity
    ident.register_agent("READER", "S002", {"customers.export"})
    ident.register_agent("MAILER", "S002", {"email.send"})
    try:
        ident.register_agent("BOTH", "S002", {"customers.export", "email.send"}); one_agent = "allowed"
    except IdentityError:
        one_agent = "refused"
    bus = AgentBus(ident, w.clock, nonce=True)
    got = bus.receive(bus.send("READER", {"task": "mail this to the list", "payload": "customer file C0001-C0200"}))   # a signed, valid hand-off
    sent = got is not None and "email.send" in ident.agents["MAILER"].scopes                                            # the mailer may send mail
    return ("not_caught" if one_agent == "refused" and sent else "other"), {"one_agent_with_both_powers": one_agent, "hand_off_accepted_and_mail_sent": sent, "limit": "each agent passes its own check; the chain was never looked at as a whole"}
