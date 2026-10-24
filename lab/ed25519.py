from __future__ import annotations
"""Ed25519 signatures in plain Python (the reference algorithm from RFC 8032, section 6), so the lab still runs
with only the standard library. It is slow and not constant-time. It is for these tests only; do not use it for real keys.
Checked against the RFC 8032 test vector and 20 random keys and messages signed with the 'cryptography' package (identical signatures)."""
import hashlib

p = 2 ** 255 - 19
d = -121665 * pow(121666, p - 2, p) % p
q = 2 ** 252 + 27742317777372353535851937790883648493


def _h(s: bytes) -> bytes:
    return hashlib.sha512(s).digest()


def _hq(s: bytes) -> int:
    return int.from_bytes(_h(s), "little") % q


def _add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C = 2 * P[3] * Q[3] * d % p
    D = 2 * P[2] * Q[2] % p
    E, F, G_, H = B - A, D - C, D + C, B + A
    return (E * F % p, G_ * H % p, F * G_ % p, E * H % p)


def _mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _eq(P, Q):
    return (P[0] * Q[2] - Q[0] * P[2]) % p == 0 and (P[1] * Q[2] - Q[1] * P[2]) % p == 0


_SQRT_M1 = pow(2, (p - 1) // 4, p)


def _recover_x(y, sign):
    if y >= p:
        return None
    x2 = (y * y - 1) * pow(d * y * y + 1, p - 2, p)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * _SQRT_M1 % p
    if (x * x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


_gy = 4 * pow(5, p - 2, p) % p
_gx = _recover_x(_gy, 0)
G = (_gx, _gy, 1, _gx * _gy % p)


def _compress(P):
    zinv = pow(P[2], p - 2, p)
    x, y = P[0] * zinv % p, P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % p)


def _expand(secret: bytes):
    h = _h(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(secret: bytes) -> bytes:
    a, _ = _expand(secret)
    return _compress(_mul(a, G))


def sign(secret: bytes, msg: bytes) -> bytes:
    a, prefix = _expand(secret)
    A = _compress(_mul(a, G))
    r = _hq(prefix + msg)
    Rs = _compress(_mul(r, G))
    s = (r + _hq(Rs + A + msg) * a) % q
    return Rs + int.to_bytes(s, 32, "little")


def verify(public: bytes, msg: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    A, R = _decompress(public), _decompress(signature[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= q:
        return False
    h = _hq(signature[:32] + public + msg)
    return _eq(_mul(s, G), _add(R, _mul(h, A)))
