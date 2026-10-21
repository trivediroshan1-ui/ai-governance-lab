# AI Governance Lab

When a company says "we govern our AI use", which of those controls actually
hold when someone tries to get around them?

This lab builds a small, open set of AI governance controls for a made-up
Indian lender, **Kaveri Finance**, and runs a fixed list of cases against them.
Every case has its expected result written down before the run. Every result is
kept, including the ones that turn out different.

It follows the same method as the
[MCP Human Approval Gateway](https://github.com/trivediroshan1-ui/mcp-human-approval-gateway)
lab.

> **What this proves, and what it doesn't.** It shows what one small, open set
> of controls did on a fixed list of cases, on made-up data. It does not show
> that any product, model or company is safe, compliant or certified. The
> mappings to laws and standards are my own reading, not legal advice.

## The four tracks in round one

| Track | What's built | The question it answers |
|---|---|---|
| **A. AI use gateway** (`lab/registry.py`, `lab/gateway.py`) | An AI use register (owner, purpose, risk tier, data allowed, model and version, approver, expiry, AI bill of materials), a gateway every model call goes through, a kill switch and a hash-chain decision log | Can the company see, approve and stop every AI use? |
| **G. Guardrail filter** (`lab/guardrail.py`) | Masks secrets and Indian personal data (Aadhaar with its checksum, PAN, cards with Luhn, phones, emails), decodes base64, reads Devanagari digits, and flags prompt injection | How much does masking really catch, and how often does it block normal work? |
| **I. Agent identity and access** (`lab/identity.py`) | Agents with their own identity and a human sponsor, short-lived signed tokens, scopes that never exceed the person an agent acts for, signed agent-to-agent messages, just-in-time privileged access and a kill switch that revokes everything | Does every agent have an owner, the least access it needs, and an off switch? |
| **E. Audit evidence** (`lab/cases.py`, `lab/controls.py`) | Reports built from the A and I logs, and a control map to ISO/IEC 42001, the NIST AI RMF, the EU AI Act and Indian rules | Could the company show an auditor proof, not a slide? |

Round one has 41 cases: A 15, G 9, I 10 and E 7. They're listed in
[`cases/round-1.json`](cases/round-1.json). Track P (consumer assistants under
one company policy) and the remaining cases come in round two.

## Run it

Python 3.10 or newer. Nothing to install.

```bash
python3 run.py --dry-run     # checks it all runs; results go to results/dry-run/ (not kept)
python3 run.py               # the real round-one run, once the guesses are committed
python3 run.py --only G4,I7  # just some cases
```

A run takes under a second and writes `results/round-1/<time>.json` and `.md`.
The JSON records the machine, Python version, git commit and the SHA-256 of
the cases file, so anyone can check the guesses came first.

See [docs/METHOD.md](docs/METHOD.md) for the method and
[docs/control-map.md](docs/control-map.md) for the control map.

## The made-up company

`data/kaveri-finance.json` has 40 staff and 200 customers, generated from a
fixed seed (`lab/data.py`), so every run sees the same company. Aadhaar, PAN
and card numbers pass the real format checks so the filter can't cheat, but
every one is invented, and each customer record is marked as test data.

## Limits

- The "models" are entries in a catalogue. Nothing is sent to a real model.
- Kill-switch timings are measured in one process on one machine. A real
  network adds its own delay.
- Shared-credential detection (case I8) assumes the gateway can tell two
  callers apart. In real life that fingerprinting is the hard part.
- The guardrail is deliberately plain (patterns, checksums, a phrase list). The
  lab measures that, rather than claiming a clever filter.
- None of this is new on its own. Gateways, masking tools, agent identity
  products and governance platforms all exist. The point is an open, tested
  reference that shows its misses.

## Round two: a better filter, and other people's tools

Round one found where the plain filter breaks. Round two does three things:

1. A second filter (`lab/guardrail_v2.py`) that fixes those gaps and leaves some on purpose.
2. Ten more guardrail cases in `cases/round-2.json`, including harmless text that should be left alone, because catching more can mean catching too much.
3. A way to run the same inputs on a tool someone else wrote.

```
python3 run.py --round 2                          # the version 2 filter
python3 run.py --round 2 --detector v1            # the round-one filter, same inputs
python3 compare.py v1 v2                          # one table, filters side by side
python3 compare.py v2 "external:python3 adapters/presidio_cmd.py"
```

Wrapping another tool takes about 20 lines: see `adapters/example_stub.py` and
`adapters/README.md`. A tool is only scored on jobs it claims to do, so a PII
library isn't marked down for not detecting prompt injection.

Read the false-alarm case (G15) together with the misses: a tool that detects
almost nothing leaves harmless text alone and looks good there.

## Licence

MIT. See [LICENSE](LICENSE).
