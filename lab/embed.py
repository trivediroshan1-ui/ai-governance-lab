from __future__ import annotations
"""Round thirteen: turning text into numbers so documents can be found by meaning.

Two embedders:
  ToyEmbedder    - a stand-in written for the lab. It counts word stems and treats a few
                   hand-written pairs as the same word (pay, earn, paid, salary). It is NOT
                   a real model; the sandbox cannot download one. It only proves the wiring.
  LocalEmbedder  - a real model that runs on the machine (sentence-transformers). The sandbox
                   cannot install or download it; the Mac run uses it.

Choose with the AGL_EMBEDDER environment variable: "toy" (default) or "st:<model name>",
for example "st:all-MiniLM-L6-v2". The name is written into the result file."""
import math
import os
import re

SAME = {"pay": "salary", "paid": "salary", "earn": "salary", "earns": "salary", "earning": "salary",
        "wage": "salary", "wages": "salary", "compensation": "salary", "salaries": "salary",
        "employees": "employee", "staff": "employee", "everyone": "employee", "bands": "band", "changing": "change", "changes": "change"}
STOP = {"the", "a", "an", "of", "for", "and", "are", "is", "how", "what", "does", "do", "to", "on", "in", "much", "who", "me", "my"}


class ToyEmbedder:
    name = "toy (word stems and a tiny synonym list; not a real model)"

    def embed(self, texts):
        out = []
        for t in texts:
            v = {}
            for w in re.findall(r"[a-z0-9]+", t.lower()):
                if w in STOP:
                    continue
                w = SAME.get(w, w)
                v[w] = v.get(w, 0) + 1
            out.append(v)
        return out


class LocalEmbedder:
    def __init__(self, model: str):
        from sentence_transformers import SentenceTransformer   # needs the package and the model files on this machine
        self.name = f"sentence-transformers {model}"
        self._m = SentenceTransformer(model)

    def embed(self, texts):
        return [list(map(float, v)) for v in self._m.encode(list(texts), normalize_embeddings=True)]


_CACHE = {}


def get_embedder(spec: str | None = None):
    """One embedder per process, so a real model is loaded once and not once per case."""
    spec = spec or os.environ.get("AGL_EMBEDDER", "toy")
    if spec not in _CACHE:
        _CACHE[spec] = _make(spec)
    return _CACHE[spec]


def _make(spec: str):
    if spec == "toy":
        return ToyEmbedder()
    if spec.startswith("st:"):
        return LocalEmbedder(spec[3:])
    raise ValueError(f"unknown embedder {spec!r}")


def cosine(a, b) -> float:
    if isinstance(a, dict):
        num = sum(x * b.get(k, 0) for k, x in a.items())
        da, db = math.sqrt(sum(x * x for x in a.values())), math.sqrt(sum(x * x for x in b.values()))
    else:
        num = sum(x * y for x, y in zip(a, b))
        da, db = math.sqrt(sum(x * x for x in a)), math.sqrt(sum(y * y for y in b))
    return num / (da * db) if da and db else 0.0
