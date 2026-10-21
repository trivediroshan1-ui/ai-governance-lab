# Control map (case E9)

My own reading of where each lab control lines up. Not legal advice, not a certification. ISO/IEC 42001 control text is copyrighted, so only Annex A numbers are given: check them against your own copy.

| ID | Control | Cases | ISO/IEC 42001 Annex A | NIST AI RMF | EU AI Act | India and other |
|---|---|---|---|---|---|---|
| C1 | AI use register with a named owner for every use | A1, A2, A3, E1, E2 | A.3.2, A.6.2.2 | GOVERN 1.6, GOVERN 2.1 | Art. 26 (deployer duties) | MeitY AI Governance Guidelines (accountability); CERT-In AI blueprint (AI asset inventory) |
| C2 | Approval by someone other than the owner; high-risk uses need an impact assessment and a person's sign-off | A6, A14, E3, E4 | A.5.2, A.5.3, A.5.4 | MAP 1.1, GOVERN 4.1 | Art. 9, Art. 14, Art. 27 | RBI FREE-AI (product vetting, accountability) |
| C3 | Approvals expire; changes to model version or risk tier force a new review | A8, A9, A11, E10 | A.6.2.6 | MANAGE 4.1 | Art. 26(5) (monitoring) | RBI FREE-AI (ongoing monitoring) |
| C4 | Personal and confidential data only to models approved for it; cross-border held for review | A4, A5 | A.7.2, A.7.4 | MEASURE 2.10 | Art. 10 (for providers); GDPR outside the Act | DPDP Act s. 8 (safeguards), s. 16 (transfers outside India) |
| C5 | Guardrail masks secrets and Indian personal data before a model sees them, and flags injection | G1, G2, G3, G4, G5, G7, G8, G9, G11 | A.7.4, A.6.2.4 | MEASURE 2.7, MEASURE 2.10 | Art. 15 (for providers) | DPDP Act s. 8; CERT-In AI blueprint (protect data processed by AI) |
| C6 | Kill switch: one use or one agent stopped at once | A12, A16, I11 | A.6.2.6 | MANAGE 2.4 | Art. 14(4)(e) (stop button) | SEBI planned kill switch; CERT-In emergency shutdown for agents |
| C7 | Tamper-evident decision log | A13, E4, E5 | A.6.2.8 | GOVERN 1.4 | Art. 12, Art. 26(6) | CERT-In directions (log retention) |
| C8 | AI bill of materials for every use | A15, E7 | A.6.2.3, A.10.3 | GOVERN 6.1 | Art. 11 (for providers) | CERT-In SBOM/AIBOM guidelines (July 2025) |
| C9 | Agents have their own identity, a human sponsor, short-lived tokens and only their scopes | I1, I2, I3, I6, I8, I10 | A.3.2, A.6.2.6 | GOVERN 2.1, MANAGE 2.4 | Art. 14 (oversight) | CERT-In AI blueprint (govern agentic systems); Singapore MGF for agentic AI |
| C10 | Agents acting for a person never exceed that person; agent-to-agent messages are signed | I4, I5, I9 | A.9.2 | MEASURE 2.7 | Art. 15 (for providers) | OWASP Agentic ASI03, ASI07 (community) |
| C11 | Privileged actions need a just-in-time grant from someone else, with a recorded session | I7 | A.9.2 | GOVERN 4.1 | Art. 14 | RBI and SEBI expectations on privileged access (existing cyber rules) |
| C12 | Incidents: timeline from detection to closure, and a report inside 6 hours | E6, E11 | A.8.4 | MANAGE 4.3 | Art. 73 (serious incidents, providers) | CERT-In 6-hour reporting; DPDP breach notice |
