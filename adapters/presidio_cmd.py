#!/usr/bin/env python3
"""Wraps Microsoft Presidio, an open-source PII detector, for the lab.

NOT YET RUN: written from Presidio's documented API and never run against it
(the build machine could not install it). Run it on your own laptop first:

    pip3 install presidio-analyzer
    python3 -m spacy download en_core_web_lg
    python3 run.py --round 2 --detector "external:python3 adapters/presidio_cmd.py"

Presidio finds personal data. It does not look for secrets or prompt
injection, so those cases show as n/a for it, not as failures. Which Indian
recognizers (IN_PAN, IN_AADHAAR) are on depends on your Presidio version; the
script uses only the ones your install has and prints which, to stderr.
"""
import json
import sys

if "--info" in sys.argv:
    print(json.dumps({"name": "presidio", "supports": ["personal"]}))
    sys.exit(0)

from presidio_analyzer import AnalyzerEngine  # noqa: E402

KIND = {"PHONE_NUMBER": "phone", "EMAIL_ADDRESS": "email", "CREDIT_CARD": "card",
        "IN_PAN": "pan", "IN_AADHAAR": "aadhaar"}
engine = AnalyzerEngine()
entities = [e for e in KIND if e in set(engine.get_supported_entities())]
print("presidio entities in use:", entities, file=sys.stderr)

for line in sys.stdin:
    text = json.loads(line)["text"]
    hits = engine.analyze(text=text, language="en", entities=entities)
    masked = text
    for h in sorted(hits, key=lambda h: h.start, reverse=True):
        masked = masked[:h.start] + f"[{KIND[h.entity_type].upper()}]" + masked[h.end:]
    print(json.dumps({"kinds": sorted({KIND[h.entity_type] for h in hits}), "masked": masked,
                      "injection": False}), flush=True)
