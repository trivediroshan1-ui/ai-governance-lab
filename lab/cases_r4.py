from __future__ import annotations
"""Round four: the guardrail cases again, on the version 3 filter.

Same inputs as rounds one to three (the functions are reused), so the only
thing that changed is the filter. Version 3 was written to fix the ten
samples version 2 missed in the round-three test set, so improvement on that
set (G17) and on the round-two variants is NOT evidence that it generalises.
That is what the held-out file is for: python3 heldout.py v1 v2 v3
"""
from .cases_r2 import CASES as R2
from .cases_r3 import CASES as R3

WANT_R2 = ["G1", "G4", "G7", "G8", "G9", "G12", "G13", "G14", "G15", "G16"]
WANT_R3 = ["G6", "G10", "G17", "I12"]

CASES = {**{k: R2[k] for k in WANT_R2}, **{k: R3[k] for k in WANT_R3}}
