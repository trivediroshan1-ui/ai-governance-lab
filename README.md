# AI Governance Lab

**Do AI governance controls actually hold, or do they only look right in a mapping sheet?**
13 rounds, 164 cases on made-up data. For every case I wrote what I expected, hashed it and committed it before the code, ran it, then switched each control off to see whether a check noticed. Mistakes stay in the record.

[Read it with diagrams and videos](https://roshantrivedi.co.in/ai-governance-lab/?utm_source=github&utm_medium=readme) ·
[Every case](https://roshantrivedi.co.in/ai-governance-lab/cases/) ·
[Every command I ran on my Mac, with output](https://roshantrivedi.co.in/ai-governance-lab/mac/) ·
[Free book, 69 pages](https://roshantrivedi.co.in/assets/ai-governance-lab-book.pdf) ·
[Rounds five to thirteen, 74 pages](https://roshantrivedi.co.in/assets/ai-governance-lab-addendum.pdf)

The company is made up (Kaveri Finance, an Indian lender). Every person, Aadhaar, PAN and card number is invented. Aadhaar and cards pass the real checks on purpose, so a filter cannot cheat. Nothing here relates to any employer or real company.

---

## Eight things the lab found

1. **Telling the model "do not reveal this" changed nothing.** A careless model repeats what it is given. What held was checking the person's *live* permissions before the documents are fetched (round 9).
2. **A plain text filter broke, and my fix only looked good on my own tests.** Three versions caught 20, 42 and 45 of 53 attack variants, but only 4 of 10 items written after the fix. The 100% on the 200-sample set was tuned to it (rounds 1 to 4).
3. **A nightly sync that replaces a whole user record can switch a disabled account back on.** A rehire that restores the old account brings the old access back too. An erasure request and a tamper-evident log pull in opposite directions (round 10).
4. **A shared secret let a compromised executor forge proofs. A public key did not.** The second agent also inherited everything the first one had, until its token was cut down to the job (round 11).
5. **Search by meaning found a restricted HR document for a question with no matching keyword.** Where the permission filter sits matters: after ranking it can return an empty answer, before ranking it returns the best allowed document (round 13).
6. **If the agent goes round the gateway, you need three layers, not one:** make it hard, notice it, answer it. A change in the identity system's own log with no signed decision behind it is the alarm (round 8).
7. **Approvals have a life cycle.** When an approver leaves, their waiting requests have to go somewhere (round 12).
8. **My own checker lied once.** It said "5 of 5 noticed" while every case had errored, because it counted an error as noticing a change. I fixed it so an error never counts, and kept the wrong file (round 13).

---

## How it stays honest

1. **Guess first.** The expected result for every case is written and committed before the code. The result file records the SHA-256 of the cases file, so anyone can check the guesses did not change afterwards.
2. **Run it.** Results are kept, including the ones that differ from the guess.
3. **Switch each control off, one at a time,** in a copy of the code, each in its own process. A case counts as "noticing" only if it passes normally and gives a different, non-error result with the control off.
4. **Two machines.** Linux sandbox and a MacBook Air, same verdicts, both files kept. Real embedding model on the Mac for round 13.
5. **Show the mistakes.** First-run files, fixed tests and a wrong checker result are all in the repository and on the website.

If every case matches my guess, I read that as a warning that the guesses were easy, not as good news about the controls.

---

## The rounds

| Round | Question | New cases | As guessed | Control-off checks | Guesses file (SHA-256, first 10) |
|---|---|---|---|---|---|
| 1 to 4 | Gateway, guardrail filter, agent identity, audit evidence, three filter versions | 59 | see the site | filters: 20, 42, 45 of 53 variants; 4 of 10 on unseen items | `cases/round-1.json` to `round-4.json` |
| 5 | What did my own identity-governance audit miss? (the "read access" claim) | 14 | 14 of 14 (I13 crashed first run: my test, fixed) | n/a | `c35063c59b` |
| 6 | An agent that sends instructions to an identity API | 18 | 18 of 18 | 12 of 12 | `47fd08c1e8` |
| 7 | HR-driven joiner, mover, leaver | 12 | 12 of 12 | 14 of 14 (first run 13 of 14: one weak test, rebuilt) | `cd132028ef` |
| 8 | What if the agent goes round the gateway? | 12 | 12 of 12 | 21 of 21 | `eda951f43e` |
| 9 | An assistant that answers from company documents | 12 | 12 of 12 (first run 11: a bug in my masking, fixed) | 12 of 12 (some weaker, stated) | `1cf564faf7` |
| 10 | Credentials, sessions and edge cases | 12 | 12 of 12 first run | 12 of 12 | `ad73f73f85` |
| 11 | Delegation, keys and organisations | 12 | 12 of 12 (first run 11: my own test, fixed) | 11 of 11 | `4fd307467d` |
| 12 | Who approved it, what exactly, and when | 7 | 7 of 7 | 6 of 6 | `96da9fc693` |
| 13 | Do the document permissions hold under search by meaning? | 6 | 6 of 6 (real model on the Mac) | 5 of 5 | `9fd8ab82ea` |

Total: **164 cases** (59 in rounds one to four, 105 in rounds five to thirteen), plus 9 requests I ran by hand on one real assistant (Track P: it followed the written policy in 9 of 9; a small test). Cases are in `cases/`, results in `results/round-N/`, code in `lab/`.

---

## Run it

Python 3.9 or newer (run on 3.9.6 and 3.11). Rounds one to twelve need nothing installed.

```bash
python3 run.py --dry-run            # checks everything runs (round one by default); results are not kept
python3 run.py --round 12           # the cases of one round -> results/round-12/<time>.json and .md
python3 run.py --round 12 --only F5 # one case
python3 mutations_r12.py            # switch each control off and check that a case notices
```

Round 13 uses an embedding model for search by meaning:

```bash
python3 run.py --round 13                              # built-in word-stem stand-in: proves only that the code works
pip3 install sentence-transformers "numpy<2"           # numpy 2 breaks the torch build I used
AGL_EMBEDDER=st:all-MiniLM-L6-v2 python3 run.py --round 13
AGL_EMBEDDER=st:all-MiniLM-L6-v2 python3 mutations_r13.py
```

A row marked "different" means the result did not match my guess. That is a finding, not an error. The result file records the machine, Python version, git commit, embedder and the SHA-256 of the cases file. Rounds one to four (filters, comparison scripts, Track P) are described in [docs/rounds-1-to-4.md](docs/rounds-1-to-4.md). The method is in [docs/METHOD.md](docs/METHOD.md) and the control map to ISO 27001, NIST, PCI DSS and HIPAA in [docs/control-map.md](docs/control-map.md).

---

## Where to start

- **You have five minutes.** Watch the [one-minute architecture video](https://roshantrivedi.co.in/ai-governance-lab/), then read the eight findings above.
- **You are an auditor or a control owner.** Read the control map and the "What held / What broke / What this does not show" blocks on each round. Check that a hash on the page equals the file's SHA-256.
- **You are an engineer.** Run `python3 run.py --dry-run`, then one round, then its `mutations_rN.py`. Read `lab/gateway.py` and `lab/rag.py`.
- **You want to break it.** Pick a round, write your expected result first, and [propose the case](https://github.com/trivediroshan1-ui/ai-governance-lab/issues/new) (see below). The two blind spots I already know are listed under limits.
- **You work on identity at a company.** The real question is which of these would you test first against a real system. That is the next step I cannot take alone.

---

## What this does not show

- The "models", the vault, the directory, the identity API and the approval queue are small models I wrote. Real products behave differently.
- No AI model was tested in most rounds. One real assistant was tested by hand in a small test (Track P).
- I wrote both the guesses and the code, so "as expected" means the rules do what I built them to do, not that I thought of every attack. The value comes from the cases other people add.
- Timings and hashes come from one process on one machine.
- Two things the lab cannot see: two documents that are each fine to read but add up to a secret, and two people who approve each other's requests.
- The mappings to laws and standards are my own reading, not legal advice and not a certification.
- None of this is new on its own. Gateways, masking tools, agent identity products and governance platforms exist. The point is an open, tested reference that shows its misses.

---

## Propose a case, cite, licence

Write a case I did not think of: say what happens, write your expected result **before** you look at the code, use made-up data only, and open an issue. If it is good, it goes into the next round with your name on it.

If you use this, please cite it as: *Roshan Trivedi, "AI Governance Lab", 2026, https://github.com/trivediroshan1-ui/ai-governance-lab*.

MIT licence. See [LICENSE](LICENSE). Built by [Roshan Trivedi](https://roshantrivedi.co.in): privileged access and identity for 14+ years, now testing AI governance in the open.
