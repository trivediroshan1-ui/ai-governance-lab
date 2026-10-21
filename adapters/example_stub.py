#!/usr/bin/env python3
"""The smallest possible outside tool, for testing the harness. It only finds
email addresses. Copy this file to wrap a real tool.

    python3 adapters/example_stub.py --info     # who am I, what do I claim to do
    python3 adapters/example_stub.py --serve    # read JSON lines, answer JSON lines

Request:  {"text": "..."}
Answer:   {"kinds": ["email", ...], "masked": "...", "injection": false}
Kinds the lab understands: secret, aadhaar, pan, card, phone, email.
"""
import json
import re
import sys

if "--info" in sys.argv:
    print(json.dumps({"name": "stub-email-only", "supports": ["personal"]}))
    sys.exit(0)

EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
for line in sys.stdin:
    text = json.loads(line)["text"]
    kinds = ["email"] if EMAIL.search(text) else []
    print(json.dumps({"kinds": kinds, "masked": EMAIL.sub("[EMAIL]", text), "injection": False}), flush=True)
