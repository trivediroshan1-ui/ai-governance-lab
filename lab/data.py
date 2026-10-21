from __future__ import annotations
"""Kaveri Finance: a made-up Indian lender, its staff and its customers.

Same seed, same company, every time, so every run sees the same data.
"""
import json
import random
from pathlib import Path

from . import ids

SEED = 20261021
TEST_MARK = "MADE-UP TEST DATA - NOT A REAL PERSON"

FIRST = ["Aarav", "Diya", "Ishaan", "Meera", "Kabir", "Anaya", "Rohan", "Saanvi", "Vihaan", "Tara",
         "Arjun", "Nisha", "Dev", "Kavya", "Aditya", "Riya", "Karan", "Pooja", "Neel", "Zara"]
LAST = ["Iyer", "Sharma", "Reddy", "Nair", "Gupta", "Menon", "Patel", "Rao", "Das", "Kulkarni"]
TEAMS = ["Lending", "Collections", "Risk", "HR", "IT", "Security", "Marketing", "Support"]


def company(seed: int = SEED) -> dict:
    rng = random.Random(seed)
    staff = []
    for i in range(40):
        name = f"{rng.choice(FIRST)} {rng.choice(LAST)}"
        staff.append({
            "id": f"S{i + 1:03d}",
            "name": name,
            "email": f"s{i + 1:03d}@kaveri.example",
            "team": TEAMS[i % len(TEAMS)],
            "active": True,
            "role": "approver" if i % 10 == 0 else "staff",
        })
    customers = []
    for i in range(200):
        customers.append({
            "id": f"C{i + 1:04d}",
            "name": f"{rng.choice(FIRST)} {rng.choice(LAST)}",
            "aadhaar": ids.make_aadhaar(rng),
            "pan": ids.make_pan(rng),
            "card": ids.make_card(rng),
            "phone": ids.make_phone(rng),
            "email": f"customer{i + 1:04d}@mail.example",
            "note": TEST_MARK,
        })
    return {"name": "Kaveri Finance (made up)", "note": TEST_MARK, "staff": staff, "customers": customers}


def write(path: Path, seed: int = SEED) -> None:
    path.write_text(json.dumps(company(seed), indent=2))
