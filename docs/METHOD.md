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

## Round three

Same rule: guesses in `cases/round-3.json` are committed before the first run.
Two cases carry a "finding" in their details that is worth reading even when
the verdict is "as expected": E5 (a hash chain cannot see lines cut off the
end without an anchor kept elsewhere) and I10 (flagging an idle agent does not
remove its access). E12 reports what a label does not survive: copy-paste, a
system that strips unknown tags, and one changed word.

Changes to the lab itself while building round three, so nothing is hidden:
models now need a supplier review on file before use (E7, seeded for both
existing models), the register can require an AI notice on customer-facing
uses (E8), a use can name a fallback model (E14), the gateway can screen a
model's answer (G10), the log can be pruned after its retention period and
anchored (E5), and a brand-new agent is no longer counted as idle on day 0
(I10). Rounds one and two give the same results as before these changes.

## Round four and held-out variants

Version 3 is a patch for known misses. The honest measure of whether a filter
works is how it does on inputs its author has not seen. `cases/held-out.json`
holds variants written by someone other than the filter's author, committed
before the filters run on them. If v3 scores no better than v2 on those, the
round-three improvement was fitting the test set, and that is worth saying
in public. Known limits of v3: UPI detection uses a list of common handles, so
a new handle is missed; the spaced-PAN rule needs capitals; the `91` phone
prefix can also match other 12-digit numbers that start with 91.
