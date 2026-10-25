# Changelog

One entry per round. The guesses hash is the first 10 characters of the SHA-256 of the round's cases file, committed before the code. Full hashes are in each round's result file.

| Round | Question | Cases | As guessed | Control-off checks | Guesses hash | Merged in |
|---|---|---|---|---|---|---|
| 13 | Do document permissions hold under search by meaning? | 6 | 6 of 6 (real model on the Mac) | 5 of 5 | `9fd8ab82ea` | #6, #7, #10, #11 |
| 12 | Who approved it, what exactly, and when | 7 | 7 of 7 | 6 of 6 | `96da9fc693` | #4, #5 (Mac run: #8, open) |
| 11 | Delegation, keys and organisations | 12 | 12 of 12 (first run 11: my own test, fixed) | 11 of 11 | `4fd307467d` | |
| 10 | Credentials, sessions and edge cases | 12 | 12 of 12 first run | 12 of 12 | `ad73f73f85` | |
| 9 | An assistant that answers from company documents | 12 | 12 of 12 (first run 11: a bug in my masking, fixed) | 12 of 12 | `1cf564faf7` | #9 |
| 8 | What if the agent goes round the gateway? | 12 | 12 of 12 | 21 of 21 | `eda951f43e` | #2 |
| 7 | HR-driven joiner, mover, leaver | 12 | 12 of 12 | 14 of 14 (first run 13 of 14: one weak test, rebuilt) | `cd132028ef` | |
| 6 | An agent that sends instructions to an identity API | 18 | 18 of 18 | 12 of 12 | `47fd08c1e8` | |
| 5 | What did my own identity-governance audit miss? | 14 | 14 of 14 (one test crashed first run, fixed) | n/a | `c35063c59b` | #1 |
| 1 to 4 | Gateway, guardrail filter, agent identity, audit evidence | 59 | see the site | filters: 20, 42, 45 of 53; 4 of 10 unseen | | |

Also merged: #3 (stronger checks).

Also: Track P, 9 requests run by hand on one real assistant (followed the written policy in 9 of 9; a small test).

Front page README rewritten: #12 (`66e4a3e`, 25 Oct 2026).
