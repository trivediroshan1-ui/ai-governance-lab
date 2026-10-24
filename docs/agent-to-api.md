# Agents that send instructions to an identity API (round six)

The pattern the lab tests, in plain words:

1. The agent does not act on identities itself. It sends a small structured request, for example `disable_user` with a staff ID.
2. A gateway outside the agent checks who the agent is, the shape of the request, the policy, the rate and, for risky actions, a human approval from someone who is not the agent's sponsor. It then signs a decision.
3. A separate executor (ordinary code, its own identity) checks the signature, takes a short-lived credential from the vault, calls the API and gives the credential back.
4. The agent never sees the credential. The log keeps who asked, who approved and what ran, with no names, e-mail addresses, free text or secrets.

What is real and what is modelled: the vault and the identity API in `lab/actions.py` are small models. They are not HashiCorp Vault, Delinea Secret Server or a SCIM product. The AI model behind an agent is not tested; cases assume it was fooled or wrong.

Not tested: real SCIM calls, a real vault, real approval screens and people, asymmetric signatures or mutual TLS between gateway and executor, multi-step agent plans, and a gateway that is itself compromised.

Case T15 shows a limit: a valid but wrong request (the wrong person with the same name) passes every check. T18 is shown by construction, not found by testing.

Run: `python3 run.py --round 6` and `python3 mutations_r6.py` (switches one control off at a time to check each case notices).
