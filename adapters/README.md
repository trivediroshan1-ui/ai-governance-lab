# Wrapping another tool

The lab talks to an outside tool through a small command. Your command must:

- `--info` print one line of JSON: `{"name": "mytool", "supports": ["personal"]}`
  (jobs it claims: `secrets`, `personal`, `injection`)
- `--serve` read one JSON request per line on stdin, `{"text": "..."}`, and
  write one JSON answer per line on stdout:
  `{"kinds": ["phone", "email"], "masked": "...", "injection": false}`

Kinds the lab understands: `secret`, `aadhaar`, `pan`, `card`, `phone`, `email`.
Flush stdout after every line. Load models once, before the loop.

Then:

```
python3 run.py --round 2 --detector "external:python3 adapters/mytool_cmd.py"
python3 compare.py v2 "external:python3 adapters/mytool_cmd.py"
```

`example_stub.py` is the smallest working example (tested).
`presidio_cmd.py` wraps Microsoft Presidio and has **not been run yet**.
Open Indian tools such as bharat-pii and sakshi-pii-in need a wrapper too;
check their own docs for the calls to make, since the lab does not guess them.
