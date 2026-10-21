# How the lab is run

The method is the MCP lab's: write the guess, run the script, record the
result, fix, run again.

1. **Write the guess first.** Every case's expected result lives in
   `cases/round-1.json`. Read it, change any guess you disagree with, and
   commit it **before** the run. The results file records the cases file's
   SHA-256, so anyone can check the guesses weren't changed afterwards.
2. **Run.** `python3 run.py`. It writes `results/round-1/<time>.json` (every
   detail) and `.md` (the table).
3. **Verdicts.** Four words, as in the MCP lab:
   - *as expected*: the result matched the guess
   - *different*: it didn't, which is often the most useful row
   - *for information*: a number to report, not a pass or fail
   - *not run*: the case crashed or isn't built yet
4. **Fix, then run again.** Fixes go in as their own commits, then the whole
   round is re-run. The before and after is the story.
5. **Second machine.** Run it on the MacBook as well and keep both results.

## Ground rules

- Kaveri Finance is made up. Every person, customer and ID number is invented,
  and the data file says so on every customer record. ID numbers pass the real
  format checks on purpose, so the filter can't cheat.
- Nothing here connects to a real model, company or account. The "models" are
  entries in a catalogue; the gateway decides, nothing is sent anywhere.
- Personal laptop and personal accounts only. Check the employer's publication
  policy before anything goes public.
- Every mapping to a law or standard is my reading, not legal advice.

## What a dry run is

`python3 run.py --dry-run` checks the code runs end to end. Its results go to
`results/dry-run/`, which git ignores, because they come before the guesses are
final and aren't the lab's result.

## Round two

The guesses for round two are in `cases/round-2.json` and, as in round one,
get committed before the run. One honest limit: the author wrote the filter
and the first draft of the guesses, so the draft guesses match the code by
construction. The value comes from your own guesses, from harder variants you
add, and from running the same inputs on tools nobody here wrote. Add your own
variants to G12, G13 and G14 from what you have seen in real Indian data
before you run.
