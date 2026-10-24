from __future__ import annotations
"""Round thirteen: search by meaning in the document-answering assistant (cases S1 to S6).
The expected results were committed in cases/round-13.json before this file existed.
The embedder is chosen with AGL_EMBEDDER (see lab/embed.py); the answer model is not tested.
Each function takes a detector (not used) and returns (outcome, details)."""
from .rag import Rag
from .world import World

CASES = {}
HR, SUPPORT = "S004", "S008"
SECRET = "band changes"
PAY_Q = "what are employees paid, how are pay bands changing"


def case(cid):
    def wrap(fn):
        CASES[cid] = fn
        return fn
    return wrap


def _rag(**kw):
    w = World()
    return w, Rag(w.staff, retriever="embed", **kw)


def _keyword_would_find(q):
    w = World()
    return any(c["doc"] == "D2" for c in Rag(w.staff).retrieve(q, SUPPORT)[0])


@case("S1")
def s1(det):
    _, none = _rag(perm="none")
    leak = SECRET in none.answer(PAY_Q, SUPPORT)["text"]
    _, live = _rag(perm="pre_live")
    held = SECRET not in live.answer(PAY_Q, SUPPORT)["text"]
    return ("meaning_search_leaks_hr_text_live_check_holds" if leak and held else "other"), {"leaks_with_no_check": leak, "held_with_live_check": held, "keyword_search_would_have_found_it": _keyword_would_find(PAY_Q)}


@case("S2")
def s2(det):
    _, a = _rag(perm="pre_live", sources="all_matches")
    _, b = _rag(perm="pre_live", sources="allowed_only")
    shown = "Salary review 2026" in a.answer(PAY_Q, SUPPORT)["sources"]
    hidden = "Salary review 2026" not in b.answer(PAY_Q, SUPPORT)["sources"]
    return ("title_leaks_when_all_matches_shown" if shown and hidden else "other"), {"title_shown_with_all_matches": shown, "title_hidden_with_allowed_only": hidden}


@case("S3")
def s3(det):
    _, after = _rag(perm="pre_live", top_k=1, rank_filter="after")
    _, before = _rag(perm="pre_live", top_k=1, rank_filter="before")
    a = after.answer(PAY_Q, SUPPORT)
    b = before.answer(PAY_Q, SUPPORT)
    ok = a["docs"] == [] and b["docs"] != [] and SECRET not in b["text"]
    return ("filter_after_ranking_gives_empty_answer_filter_before_does_not" if ok else "other"), {"filter_after_docs": a["docs"], "filter_before_docs": b["docs"], "restricted_text_in_before": SECRET in b["text"]}


@case("S4")
def s4(det):
    q = "customer asked to review address, Aadhaar number on file"
    _, nomask = _rag(perm="pre_live", mask=False)
    _, mask = _rag(perm="pre_live", mask=True)
    t1, t2 = nomask.answer(q, SUPPORT)["text"], mask.answer(q, SUPPORT)["text"]
    shown, hidden = "D5" in nomask.answer(q, SUPPORT)["docs"] and "[AADHAAR]" not in t1 and any(ch.isdigit() for ch in t1), "[AADHAAR]" in t2
    return ("aadhaar_shown_without_mask_hidden_with_mask" if shown and hidden else "other"), {"number_in_answer_without_mask": shown, "masked_with_mask": hidden}


@case("S5")
def s5(det):
    _, stale = _rag(perm="pre_index")
    stale.move(HR, "Support")
    before = SECRET in stale.answer(PAY_Q, HR)["text"]
    _, live = _rag(perm="pre_live")
    live.move(HR, "Support")
    held = SECRET not in live.answer(PAY_Q, HR)["text"]
    return ("stale_copy_still_leaks_live_check_holds" if before and held else "other"), {"stale_copy_leaks": before, "live_check_holds": held}


@case("S6")
def s6(det):
    _, r = _rag(perm="pre_live", top_k=4)
    a = r.answer("how much is Meera Iyer paid on the Risk review panel", SUPPORT)
    both = "Meera Iyer" in a["text"] and "band 9" in a["text"]
    return ("combination_not_caught" if both else "other"), {"answer_joins_name_and_pay": both, "docs": a["docs"]}
