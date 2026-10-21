from __future__ import annotations
"""A labelled test set of 200 made-up samples: 100 that hold sensitive data
and 100 harmless look-alikes. Every number is invented and either passes or
fails the real checksum on purpose. Same seed, same set, every time. Used to
turn a filter's behaviour into two numbers: catch rate and false-alarm rate
(G17), and to run the same set through other tools (G18)."""
import base64
import random

from . import ids

SEED = 20261021


def _w(rng, s, n=4):
    return rng.choice(["Customer", "Please check", "From the form:", "Note:", "Ref", "bhai", "Details -"]) + " " + s


def build(seed: int = SEED) -> list[dict]:
    rng = random.Random(seed)
    S, H = [], []

    def pos(kind, text):
        S.append({"label": "sensitive", "kind": kind, "text": text})

    def neg(kind, text):
        H.append({"label": "harmless", "kind": kind, "text": text})

    full = {ord(str(d)): chr(0xFF10 + d) for d in range(10)}
    dev = str.maketrans("0123456789", "०१२३४५६७८९")
    # --- sensitive: Aadhaar (20)
    for i in range(20):
        a = ids.make_aadhaar(rng)
        f = i % 10
        text = [a, f"{a[:4]} {a[4:8]} {a[8:]}", f"{a[:4]}-{a[4:8]}-{a[8:]}", f"{a[:4]}.{a[4:8]}.{a[8:]}",
                " ".join(a), f"scan_{a}.pdf", a.translate(dev), f"mera aadhaar {a[:4]} {a[4:8]} {a[8:]} hai",
                f"Aadhaar: {a}", f"UID {a[:4]} {a[4:8]} {a[8:]}"][f]
        pos("aadhaar", _w(rng, text))
    # --- PAN (15)
    for i in range(15):
        p = ids.make_pan(rng)
        f = i % 5
        text = [f"PAN {p}", f"pan no. {p.lower()}", f"{p}", f"PAN: {p[:5]} {p[5:9]} {p[9]}", f"1,Aarav,{p},9"][f]
        pos("pan", _w(rng, text))
    # --- phone (20)
    for i in range(20):
        ph = ids.make_phone(rng)
        f = i % 10
        text = [ph, f"+91 {ph}", f"+91-{ph[:5]}-{ph[5:]}", f"{ph[:5]} {ph[5:]}", f"0{ph}", f"(+91) {ph[:5]} {ph[5:]}",
                f"91{ph}", ph.translate(full), f"+91{ph}", f"{ph[:3]}-{ph[3:6]}-{ph[6:]}"][f]
        pos("phone", _w(rng, f"call {text}"))
    # --- card (15)
    for i in range(15):
        c = ids.make_card(rng)
        f = i % 5
        text = [c, f"{c[:4]} {c[4:8]} {c[8:12]} {c[12:]}", f"{c[:4]}-{c[4:8]}-{c[8:12]}-{c[12:]}",
                f"{c[:4]} {c[4:8]} {c[8:12]} {c[12:]}", f"card {c}"][f]
        pos("card", _w(rng, text))
    # --- email and UPI (10)
    for i in range(10):
        n = rng.randint(100, 999)
        text = [f"priya.k{n}@mail.example", f"rohan+loans{n}@kaveri.example", f"Meera{n}@Mail.Example",
                f"customer{n}@mail.example", f"pay to dev{n}@okhdfcbank"][i % 5]
        pos("email", _w(rng, text))
    # --- secrets (20)
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    for i in range(20):
        r = lambda n: "".join(rng.choice(letters) for _ in range(n))
        f = i % 10
        text = [f"key AKIA{r(16)}", f"token ghp_{r(36)}", f"postgres://admin:Kv{r(6)}@db.kaveri.example:5432/loans",
                f"jwt eyJ{r(12)}.eyJ{r(14)}.{r(20)}", f"xoxb-{rng.randint(10**9, 10**10 - 1)}-{r(12)}",
                f"export API_KEY=kv_live_{r(20).lower()}", f"DB_PASSWORD=Kv{r(8)}!",
                f'{{"client_secret": "{r(24).lower()}"}}', f"-----BEGIN PRIVATE KEY-----\n{r(40)}\n-----END PRIVATE KEY-----",
                f"auth {base64.b64encode(('AKIA' + r(16)).encode()).decode()}"][f]
        pos("secret", text)
    # --- harmless (100)
    for _ in range(10): neg("invoice number", f"Invoice {ids.make_bad_aadhaar(rng)} is due on the 30th.")
    for _ in range(6):  neg("tracking number", f"Courier tracking {rng.randint(10**15, 10**16 - 1)} has left the hub.")
    for _ in range(6):  neg("account number", f"Branch account ref {rng.randint(10**9, 6 * 10**9)} was opened last year.")
    for i in range(12):
        neg("date or amount", ["Due on 2026-11-02 at 09:00.", f"Loan of ₹{rng.randint(1, 99)},{rng.randint(10, 99)},{rng.randint(100, 999)} sanctioned.",
                               f"EMI of Rs. {rng.randint(1000, 99999):,} on the {rng.randint(1, 28)}th."][i % 3])
    for _ in range(8):  neg("pin or order id", f"Ship to PIN {rng.randint(110001, 855999)}, order {rng.randint(1000, 9999)}.")
    for _ in range(8):  neg("version or commit", f"Release {rng.randint(1, 9)}.{rng.randint(0, 20)}.{rng.randint(0, 9)} commit {''.join(rng.choice('0123456789abcdef') for _ in range(12))}.")
    for _ in range(4):  neg("toll-free", f"Call the helpline 1800 {rng.randint(100, 999)} {rng.randint(1000, 9999)}.")
    for _ in range(5):  neg("asset tag", f"Laptop asset tag KAV{rng.choice('PCHFATBLJG')}{rng.choice('ABCDEFGHJKLMNPRSTUVWXYZ')}{rng.randint(1000, 9999)}{rng.choice('ABCDEFGH')} is in store room 2.")
    for t in ["The password policy needs 12 characters and a change every 90 days.", "Rotate the API key every quarter and store it in the vault.",
              "Secret santa is on Friday in the canteen.", "Our token economy report is due next week.",
              "Use a long passphrase, never the same one twice.", "The key risk this quarter is vendor concentration.",
              "Please keep your Aadhaar and PAN details private and never paste them into a chat tool.",
              "Reset your password from the self-service page.", "The private key ceremony is scheduled for Monday.",
              "Customers ask us to explain how their credit score is used.", "Bearer tokens must be short-lived.",
              "Remember to attach the signed form before submitting."]:
        neg("sentence about secrets", t)
    for _ in range(4):  neg("ISBN", f"ISBN 978-{rng.randint(0, 9)}-{rng.randint(10000, 99999)}-{rng.randint(100, 999)}-{rng.randint(0, 9)} is on the reading list.")
    for _ in range(6):  neg("product code", f"Part code KV-{rng.randint(100, 999)}-{rng.randint(1000, 9999)}-{rng.choice('ABCDEFGH')} is back in stock.")
    for t in ["मुझे अपने लोन की किस्त की तारीख बताइए।", "bhai mera EMI kab katega, thoda check karo", "आज शाखा में भीड़ बहुत है।",
              "form bhar diya hai, bas signature baaki hai", "ग्राहक सेवा सोमवार से शनिवार तक खुली है।", "kal subah meeting hai, time yaad rakhna",
              "कृपया अपना पासवर्ड किसी से साझा न करें।", "loan ka status pata karna hai"]:
        neg("hindi or hinglish", t)
    for n in ["scan_2026_10_21.pdf", "report_final_v3.xlsx", "IMG_20261021_0045.jpg", "statement-Oct-2026.pdf", "kaveri_policy_v12.docx"]:
        neg("file name", f"Attached: {n}")
    for _ in range(3):  neg("uuid", "Request id " + "-".join("".join(rng.choice("0123456789abcdef") for _ in range(k)) for k in (8, 4, 4, 4, 12)))
    for _ in range(3):  neg("ifsc", f"Branch IFSC KVRB0{rng.randint(100000, 999999)}.")
    assert len(S) == 100 and len(H) == 100, (len(S), len(H))
    out = []
    for i, s in enumerate(S + H, start=1):
        out.append({"id": f"T{i:03d}", **s})
    return out


def score(det, samples: list[dict] | None = None) -> dict:
    samples = samples or build()
    hit = {}
    for s in samples:
        r = det.check(s["text"])
        hit[s["id"]] = bool(r.findings)
    jobs = getattr(det, "supports", {"secrets", "personal", "injection"})
    job = lambda kind: "secrets" if kind == "secret" else "personal"
    # a tool is scored only on what it claims to do
    pos = [s for s in samples if s["label"] == "sensitive" and job(s["kind"]) in jobs]
    neg = [s for s in samples if s["label"] == "harmless"]
    caught = sum(hit[s["id"]] for s in pos)
    false = sum(hit[s["id"]] for s in neg)
    by_kind = {}
    for s in pos:
        k = by_kind.setdefault(s["kind"], [0, 0]); k[1] += 1; k[0] += hit[s["id"]]
    false_by_kind = {}
    for s in neg:
        if hit[s["id"]]:
            false_by_kind[s["kind"]] = false_by_kind.get(s["kind"], 0) + 1
    return {"catch_rate": caught / len(pos), "false_alarm_rate": false / len(neg), "caught": caught, "false_alarms": false,
            "by_kind": {k: f"{a} of {b}" for k, (a, b) in by_kind.items()}, "false_alarm_kinds": false_by_kind,
            "n_sensitive": len(pos), "n_harmless": len(neg)}
