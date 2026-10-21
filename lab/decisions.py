from __future__ import annotations
"""A toy lending decision with the two things people are owed when the answer
is no: a plain explanation, and a way to ask a person to look again (E13).
The rules are made up and deliberately simple."""
from datetime import timedelta

PLAIN = {
    "dti": "Your monthly loan payments are high compared with your income.",
    "history": "Your credit history is shorter than we need to judge this loan.",
    "missed": "Recent missed payments appear on your record.",
}
REVIEW_DAYS = 30


def decide(decision_id: str, applicant: dict) -> dict:
    reasons = []
    if applicant["monthly_debt"] > 0.5 * applicant["monthly_income"]:
        reasons.append("dti")
    if applicant["history_months"] < 12:
        reasons.append("history")
    if applicant["missed_payments"] >= 2:
        reasons.append("missed")
    return {"id": decision_id, "applicant": applicant["id"], "outcome": "declined" if reasons else "approved",
            "reasons": reasons, "model_score": 0.31}     # the score is internal and is not shown


def explanation(d: dict) -> str:
    if d["outcome"] == "approved":
        return "Your loan is approved."
    lines = ["We are sorry, we could not approve your loan. The main reasons:"]
    lines += [f"- {PLAIN[r]}" for r in d["reasons"]]
    lines.append(f"This decision was made with the help of an automated system. You can ask a person at Kaveri "
                 f"Finance to review it within {REVIEW_DAYS} days, by replying to this message or calling the "
                 f"branch. Asking does not affect your other applications.")
    return "\n".join(lines)


class ReviewDesk:
    def __init__(self, staff: list[dict], log, clock):
        self.reviewers = [s for s in staff if s["team"] == "Risk" and s["active"]]
        self.log, self.clock = log, clock
        self.tickets: list[dict] = []

    def ask(self, decision: dict, by: str) -> dict:
        t = {"id": f"REV-{len(self.tickets) + 1:03d}", "decision": decision["id"], "asked_by": by,
             "reviewer": self.reviewers[len(self.tickets) % len(self.reviewers)]["id"],
             "due": (self.clock() + timedelta(days=REVIEW_DAYS)).isoformat()}
        self.tickets.append(t)
        self.log.append({"at": self.clock().isoformat(), "kind": "decision", "action": "human_review_requested",
                         "decision": decision["id"], "ticket": t["id"], "reviewer": t["reviewer"]})
        return t
