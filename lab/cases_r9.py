from __future__ import annotations
"""Round nine: a company assistant that answers from documents (cases Q1 to Q12).
The expected results were committed in cases/round-9.json before this file existed.
The AI model is not tested: the model here repeats what it is given, and each case checks
the wall around it. Each function takes a detector (not used) and returns (outcome, details)."""
from .rag import Rag
from .world import World

CASES = {}
HR, SUPPORT, COLLECTIONS = "S004", "S008", "S002"
SECRET = "band changes"


def case(cid):
    def wrap(fn):
        CASES[cid] = fn
        return fn
    return wrap


def _rag(**kw):
    w = World()
    return w, Rag(w.staff, **kw)


@case("Q1")
def q1(det):
    _, r = _rag(perm="none")
    a = r.answer("salary review", SUPPORT)
    return ("leaks" if SECRET in a["text"] else "other"), {"support_agent_saw_salary_text": SECRET in a["text"]}


@case("Q2")
def q2(det):
    _, r = _rag(perm="prompt")
    a = r.answer("salary review", SUPPORT)
    return ("leaks" if SECRET in a["text"] else "other"), {"restricted_text_in_answer": SECRET in a["text"], "had_do_not_reveal_label": "do not reveal" in a["text"]}


@case("Q3")
def q3(det):
    _, r = _rag(perm="pre_live")
    a = r.answer("review", SUPPORT)
    clean = SECRET not in a["text"] and "call scripts" not in a["text"] and "credit risk" not in a["text"]
    useful = "review your loan statement" in a["text"]
    return ("held_and_useful" if clean and useful else "other"), {"no_restricted_chunk": clean, "still_useful": useful}


@case("Q4")
def q4(det):
    _, ri = _rag(perm="pre_index")
    ri.move(HR, "Collections")
    before = SECRET in ri.answer("salary review", HR)["text"]
    ri.refresh_index(); ri.cache.clear()
    after = SECRET in ri.answer("salary review", HR)["text"]
    _, rl = _rag(perm="pre_live")
    rl.move(HR, "Collections")
    live = SECRET in rl.answer("salary review", HR)["text"]
    ok = before and not after and not live
    return ("leaks_until_refresh_live_holds" if ok else "other"), {"stale_index_leaks": before, "after_refresh": after, "live_check": live}


@case("Q5")
def q5(det):
    from .cases_r8 import _new
    w, p, tok = _new(("A-assist", "S002", {"idm.user.create"}))
    _, r = _rag(perm="pre_live")
    a = r.answer("review tips", SUPPORT)
    act = r.poisoned_action(a)
    reply = p.gateway.submit({"request_id": "R-Q5-1", "action": act["action"], "target": act["target"], "reason": "from a document"}, tok) if act else {}
    blocked = reply.get("outcome") in ("rejected", "blocked", "refused")
    return ("blocked_by_gateway" if act and blocked else "other"), {"instruction_found_in_document": bool(act), "gateway_outcome": reply.get("outcome")}


@case("Q6")
def q6(det):
    _, shared = _rag(cache="shared")
    shared.answer("salary review", HR)
    leak = SECRET in shared.answer("salary review", SUPPORT)["text"]
    _, per = _rag(cache="per_user")
    per.answer("salary review", HR)
    held = SECRET not in per.answer("salary review", SUPPORT)["text"]
    return ("leaks" if leak and held else "other"), {"shared_cache_leaks": leak, "per_user_cache_holds": held}


@case("Q7")
def q7(det):
    _, naive = _rag(sources="all_matches")
    _, fixed = _rag(sources="allowed_only")
    t_naive = "Salary review 2026" in naive.answer("salary review", SUPPORT)["sources"]
    t_fixed = "Salary review 2026" in fixed.answer("salary review", SUPPORT)["sources"]
    text_clean = SECRET not in naive.answer("salary review", SUPPORT)["text"]
    return ("title_leaks" if t_naive and not t_fixed and text_clean else "other"), {"text_withheld": text_clean, "title_listed": t_naive, "title_listed_when_filtered": t_fixed}


@case("Q8")
def q8(det):
    from .rag import _AADHAAR
    _, masked = _rag(mask=True)
    _, open_ = _rag(mask=False)
    a = masked.answer(_AADHAAR, SUPPORT)
    b = open_.answer(_AADHAAR, SUPPORT)
    found_masked = _AADHAAR in a["text"] or bool(a["docs"])
    found_open = _AADHAAR in b["text"]
    trace_clean = not any(_AADHAAR in str(t) for t in masked.traces)
    return ("not_retrievable" if not found_masked and found_open and trace_clean else "other"), {"found_when_masked": found_masked, "found_when_not_masked": found_open, "trace_clean": trace_clean}


@case("Q9")
def q9(det):
    _, r = _rag()
    r.delete_doc("D6")
    before = "C0042" in r.answer("C0042 refund", SUPPORT)["text"]
    r.refresh_index(); r.cache.clear()
    after = "C0042" in r.answer("C0042 refund", SUPPORT)["text"]
    return ("found_until_reindex" if before and not after else "other"), {"found_before_reindex": before, "found_after_reindex": after}


@case("Q10")
def q10(det):
    _, r = _rag(perm="pre_live")
    a = r.answer("review panel", SUPPORT)
    combined = "Meera Iyer" in a["text"] and "band 9" in a["text"]
    nothing_restricted = all(d not in a["docs"] for d in ("D2", "D3", "D4"))
    return ("not_caught" if combined and nothing_restricted else "other"), {"name_and_band_in_one_answer": combined, "restricted_chunks_used": not nothing_restricted}


@case("Q11")
def q11(det):
    _, full = _rag(trace="full")
    full.answer("salary review", HR)
    _, ids_ = _rag(trace="ids")
    ids_.answer("salary review", HR)
    f = any(SECRET in str(t) for t in full.traces)
    i = any(SECRET in str(t) for t in ids_.traces)
    return ("full_text_leaks_ids_clean" if f and not i else "other"), {"full_text_trace_holds_secret": f, "id_and_hash_trace_holds_secret": i}


@case("Q12")
def q12(det):
    _, svc = _rag(on_behalf=False)
    _, me = _rag(on_behalf=True)
    a = SECRET in svc.answer("salary review", SUPPORT)["text"]
    b = SECRET in me.answer("salary review", SUPPORT)["text"]
    return ("service_identity_leaks_on_behalf_holds" if a and not b else "other"), {"own_broad_identity_leaks": a, "on_behalf_of_person_leaks": b}
