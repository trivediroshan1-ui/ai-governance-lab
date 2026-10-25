# Security

This is toy code for a public lab, not a product. The vault, directory, identity API and approval queue are small models written for testing. Do not run it against real systems or real data.

**Test data that looks like secrets.** Files in `lab/` contain fake keys, tokens and passwords on purpose (for example AWS's documented example key `AKIAIOSFODNN7EXAMPLE`). They exist so the filters have something to catch. None of them work anywhere.

**Found a real problem?**

- A real secret or real personal data in this repository: open a private report under the *Security* tab (Report a vulnerability). Please do not open a public issue.
- A vulnerability in roshantrivedi.co.in: use the contact in [security.txt](https://roshantrivedi.co.in/.well-known/security.txt).
- A weak test or a missed attack: that is not a security report, it is a case. Please [propose a case](../../issues/new/choose).
