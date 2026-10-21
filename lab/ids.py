"""Indian ID formats: checks and made-up test numbers.

Every number this file makes passes the real format checks (so a filter
can't tell it from a real one by format alone) but is invented. Files that
store them say so.
"""
import random
import re

# Verhoeff checksum, which the last digit of an Aadhaar number carries.
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_valid(number: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_digit(number: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])


def aadhaar_valid(number: str) -> bool:
    """12 digits, not starting with 0 or 1, and a correct Verhoeff check digit."""
    return bool(re.fullmatch(r"[2-9]\d{11}", number)) and verhoeff_valid(number)


def make_aadhaar(rng: random.Random) -> str:
    body = str(rng.randint(2, 9)) + "".join(str(rng.randint(0, 9)) for _ in range(10))
    return body + verhoeff_digit(body)


def make_bad_aadhaar(rng: random.Random) -> str:
    """12 digits that look like an Aadhaar number but fail the checksum."""
    good = make_aadhaar(rng)
    last = (int(good[-1]) + rng.randint(1, 9)) % 10
    return good[:-1] + str(last)


PAN_RE = re.compile(r"\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b")


def make_pan(rng: random.Random) -> str:
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return (
        "".join(rng.choice(letters) for _ in range(3))
        + "P"
        + rng.choice(letters)
        + "".join(str(rng.randint(0, 9)) for _ in range(4))
        + rng.choice(letters)
    )


def luhn_valid(number: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def make_card(rng: random.Random) -> str:
    """A 16-digit number that passes Luhn, starting 4000 (a common test range)."""
    body = "4000" + "".join(str(rng.randint(0, 9)) for _ in range(11))
    for last in range(10):
        if luhn_valid(body + str(last)):
            return body + str(last)
    raise AssertionError("unreachable")


def make_phone(rng: random.Random) -> str:
    return str(rng.choice([6, 7, 8, 9])) + "".join(str(rng.randint(0, 9)) for _ in range(9))
