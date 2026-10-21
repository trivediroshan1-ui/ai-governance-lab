"""A fresh Kaveri Finance for each case: staff, approved models, a few
registered AI uses, the gateway, the identity service and one shared log.
A lab clock lets cases move time forward without waiting."""
from datetime import datetime, timedelta, timezone

from . import data
from .gateway import Gateway
from .hashlog import HashLog
from .identity import IdentityService
from .registry import Model, Registry, Use

START = datetime(2026, 11, 2, 9, 0, tzinfo=timezone.utc)

AIBOM = {"model": "kaveri-small", "version": "1.2", "hosting": "IN", "data_sources": ["support tickets (made up)"],
         "libraries": ["lab gateway 0.1"], "supplier": "in-house stub"}


class Clock:
    def __init__(self, start: datetime = START):
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw) -> None:
        self.now += timedelta(**kw)


class World:
    def __init__(self):
        self.company = data.company()
        self.staff = self.company["staff"]
        self.clock = Clock()
        self.log = HashLog()
        self.models = [
            Model("kaveri-small", "1.2", "IN", ["public", "internal", "confidential", "personal"]),
            Model("global-large", "4.0", "US", ["public", "internal", "confidential"]),
        ]
        self.registry = Registry(self.staff, self.models, self.log, self.clock)
        self.gateway = Gateway(self.registry, self.log, self.clock)
        self.identity = IdentityService(self.staff, self.log, self.clock)
        self.approver = "S001"      # approvers: S001, S011, S021, S031
        self.approver2 = "S011"
        self._seed_uses()

    def _seed_uses(self):
        r = self.registry
        r.register(Use("U1", "support-summary", "S002", "Summarise support tickets", "low",
                       ["public", "internal", "personal"], "kaveri-small", "1.2", aibom=dict(AIBOM)))
        r.approve("U1", self.approver)
        r.register(Use("U2", "marketing-copy", "S007", "Draft marketing copy", "low",
                       ["public", "internal", "confidential"], "global-large", "4.0",
                       aibom={**AIBOM, "model": "global-large", "version": "4.0", "hosting": "US"}))
        r.approve("U2", self.approver)
        r.register(Use("U3", "collections-agent", "S003", "Agent that drafts collection reminders", "medium",
                       ["internal", "personal"], "kaveri-small", "1.2", tools=["crm.read", "email.draft"],
                       aibom=dict(AIBOM)))
        r.approve("U3", self.approver2)

    def customer(self, i: int = 0) -> dict:
        return self.company["customers"][i]
