"""The control map (case E9): each lab control, the cases that test it, and
where it lines up in the main frameworks.

This is my own reading, not legal advice and not a certification. ISO/IEC
42001 control text is copyrighted, so only its Annex A numbers are given;
check them against your own copy of the standard.
"""

CONTROLS = [
    {"id": "C1", "control": "AI use register with a named owner for every use",
     "cases": ["A1", "A2", "A3", "E1", "E2"],
     "iso42001": "A.3.2, A.6.2.2", "nist_ai_rmf": "GOVERN 1.6, GOVERN 2.1", "eu_ai_act": "Art. 26 (deployer duties)",
     "india": "MeitY AI Governance Guidelines (accountability); CERT-In AI blueprint (AI asset inventory)"},
    {"id": "C2", "control": "Approval by someone other than the owner; high-risk uses need an impact assessment and a person's sign-off",
     "cases": ["A6", "A14", "E3", "E4"],
     "iso42001": "A.5.2, A.5.3, A.5.4", "nist_ai_rmf": "MAP 1.1, GOVERN 4.1", "eu_ai_act": "Art. 9, Art. 14, Art. 27",
     "india": "RBI FREE-AI (product vetting, accountability)"},
    {"id": "C3", "control": "Approvals expire; changes to model version or risk tier force a new review",
     "cases": ["A8", "A9", "A11", "E10"],
     "iso42001": "A.6.2.6", "nist_ai_rmf": "MANAGE 4.1", "eu_ai_act": "Art. 26(5) (monitoring)",
     "india": "RBI FREE-AI (ongoing monitoring)"},
    {"id": "C4", "control": "Personal and confidential data only to models approved for it; cross-border held for review",
     "cases": ["A4", "A5"],
     "iso42001": "A.7.2, A.7.4", "nist_ai_rmf": "MEASURE 2.10", "eu_ai_act": "Art. 10 (for providers); GDPR outside the Act",
     "india": "DPDP Act s. 8 (safeguards), s. 16 (transfers outside India)"},
    {"id": "C5", "control": "Guardrail masks secrets and Indian personal data before a model sees them, and flags injection",
     "cases": ["G1", "G2", "G3", "G4", "G5", "G7", "G8", "G9", "G11"],
     "iso42001": "A.7.4, A.6.2.4", "nist_ai_rmf": "MEASURE 2.7, MEASURE 2.10", "eu_ai_act": "Art. 15 (for providers)",
     "india": "DPDP Act s. 8; CERT-In AI blueprint (protect data processed by AI)"},
    {"id": "C6", "control": "Kill switch: one use or one agent stopped at once",
     "cases": ["A12", "A16", "I11"],
     "iso42001": "A.6.2.6", "nist_ai_rmf": "MANAGE 2.4", "eu_ai_act": "Art. 14(4)(e) (stop button)",
     "india": "SEBI planned kill switch; CERT-In emergency shutdown for agents"},
    {"id": "C7", "control": "Tamper-evident decision log",
     "cases": ["A13", "E4", "E5"],
     "iso42001": "A.6.2.8", "nist_ai_rmf": "GOVERN 1.4", "eu_ai_act": "Art. 12, Art. 26(6)",
     "india": "CERT-In directions (log retention)"},
    {"id": "C8", "control": "AI bill of materials for every use",
     "cases": ["A15", "E7"],
     "iso42001": "A.6.2.3, A.10.3", "nist_ai_rmf": "GOVERN 6.1", "eu_ai_act": "Art. 11 (for providers)",
     "india": "CERT-In SBOM/AIBOM guidelines (July 2025)"},
    {"id": "C9", "control": "Agents have their own identity, a human sponsor, short-lived tokens and only their scopes",
     "cases": ["I1", "I2", "I3", "I6", "I8", "I10"],
     "iso42001": "A.3.2, A.6.2.6", "nist_ai_rmf": "GOVERN 2.1, MANAGE 2.4", "eu_ai_act": "Art. 14 (oversight)",
     "india": "CERT-In AI blueprint (govern agentic systems); Singapore MGF for agentic AI"},
    {"id": "C10", "control": "Agents acting for a person never exceed that person; agent-to-agent messages are signed",
     "cases": ["I4", "I5", "I9"],
     "iso42001": "A.9.2", "nist_ai_rmf": "MEASURE 2.7", "eu_ai_act": "Art. 15 (for providers)",
     "india": "OWASP Agentic ASI03, ASI07 (community)"},
    {"id": "C11", "control": "Privileged actions need a just-in-time grant from someone else, with a recorded session",
     "cases": ["I7"],
     "iso42001": "A.9.2", "nist_ai_rmf": "GOVERN 4.1", "eu_ai_act": "Art. 14",
     "india": "RBI and SEBI expectations on privileged access (existing cyber rules)"},
    {"id": "C12", "control": "Incidents: timeline from detection to closure, and a report inside 6 hours",
     "cases": ["E6", "E11"],
     "iso42001": "A.8.4", "nist_ai_rmf": "MANAGE 4.3", "eu_ai_act": "Art. 73 (serious incidents, providers)",
     "india": "CERT-In 6-hour reporting; DPDP breach notice"},
]


def as_markdown() -> str:
    head = "| ID | Control | Cases | ISO/IEC 42001 Annex A | NIST AI RMF | EU AI Act | India and other |\n|---|---|---|---|---|---|---|\n"
    rows = "".join(
        f"| {c['id']} | {c['control']} | {', '.join(c['cases'])} | {c['iso42001']} | {c['nist_ai_rmf']} | {c['eu_ai_act']} | {c['india']} |\n"
        for c in CONTROLS)
    return head + rows
