from __future__ import annotations
"""Search that an AI agent uses to answer a person. The question is whose
permissions the search obeys. "plain" ignores document permissions. "index"
checks a copy of the permissions taken when the files were indexed. "live"
checks the directory at the moment of the question."""

DOCS = [
    {"id": "D1", "title": "Support FAQ changes", "team": None, "text": "Public FAQ wording for loan queries."},
    {"id": "D2", "title": "Salary review 2026", "team": "HR", "text": "Salary review: band changes for every employee."},
    {"id": "D3", "title": "Collections playbook", "team": "Collections", "text": "Review of overdue accounts and call scripts."},
    {"id": "D4", "title": "Risk committee notes", "team": "Risk", "text": "Review of the credit risk model and limits."},
]


class Search:
    def __init__(self, staff: list[dict]):
        self.staff = {s["id"]: dict(s) for s in staff}          # the live directory
        self.index_teams = {s["id"]: s["team"] for s in staff}  # permissions copied at index time

    def move(self, staff_id: str, new_team: str) -> None:
        self.staff[staff_id]["team"] = new_team                 # the directory changes at once; the index copy does not

    def refresh_index(self) -> None:
        self.index_teams = {k: v["team"] for k, v in self.staff.items()}

    def search(self, query: str, user: str, mode: str = "live") -> list[str]:
        words = [w.lower() for w in query.split()]
        hits = []
        for d in DOCS:
            text = (d["title"] + " " + d["text"]).lower()
            if not any(w in text for w in words):
                continue
            if mode != "plain" and d["team"] is not None:
                team = self.staff[user]["team"] if mode == "live" else self.index_teams[user]
                if team != d["team"]:
                    continue
            hits.append(d["id"])
        return hits
