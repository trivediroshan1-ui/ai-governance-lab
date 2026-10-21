from __future__ import annotations
"""The AI use register: every approved use of AI at Kaveri Finance, with a
named owner, a purpose, a risk tier, the data it may touch, the model and
version it was approved for, who approved it and until when."""
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .hashlog import HashLog

DATA_CLASSES = ["public", "internal", "confidential", "personal"]
RISK_TIERS = ["low", "medium", "high"]
APPROVAL_DAYS = 90


@dataclass
class Model:
    name: str
    version: str
    region: str            # where it runs: "IN" or anywhere else
    allowed_data: list[str]
    review: dict | None = None   # supplier and model review on file (who, when, what)


@dataclass
class Use:
    id: str
    name: str
    owner: str | None
    purpose: str
    risk_tier: str
    data_classes: list[str]
    model: str
    model_version: str
    tools: list[str] = field(default_factory=list)
    status: str = "draft"          # draft, approved, paused, review, expired, killed
    approved_by: str | None = None
    approved_at: datetime | None = None
    risk_assessment: str | None = None
    human_signoff: str | None = None
    aibom: dict | None = None
    audience: str = "staff"          # staff or customer
    notice: str | None = None        # the "you are dealing with AI" text, for customer-facing uses
    fallback_model: str | None = None


class RegistryError(Exception):
    pass


class Registry:
    def __init__(self, staff: list[dict], models: list[Model], log: HashLog, clock):
        self.staff = {s["id"]: s for s in staff}
        self.models = {m.name: m for m in models}
        self.uses: dict[str, Use] = {}
        self.log = log
        self.clock = clock

    def _record(self, action: str, use: Use, **extra):
        self.log.append({"at": self.clock().isoformat(), "kind": "registry", "action": action,
                         "use": use.id, **extra})

    def register(self, use: Use) -> Use:
        if not use.owner or use.owner not in self.staff or not self.staff[use.owner]["active"]:
            raise RegistryError("A use needs a named, active owner.")
        if use.model not in self.models:
            raise RegistryError("Unknown model.")
        if use.risk_tier not in RISK_TIERS:
            raise RegistryError("Unknown risk tier.")
        if use.audience == "customer" and not use.notice:
            raise RegistryError("A customer-facing use needs a notice telling people they are dealing with AI.")
        if use.fallback_model and use.fallback_model not in self.models:
            raise RegistryError("Unknown fallback model.")
        self.uses[use.id] = use
        self._record("registered", use, owner=use.owner, risk_tier=use.risk_tier)
        return use

    def approve(self, use_id: str, approver: str) -> Use:
        use = self.uses[use_id]
        if approver == use.owner:
            raise RegistryError("Owners can't approve their own use.")
        if self.staff.get(approver, {}).get("role") != "approver":
            raise RegistryError("Only an approver can approve.")
        if use.risk_tier == "high" and not (use.risk_assessment and use.human_signoff):
            raise RegistryError("High-risk uses need a risk assessment and a person's sign-off first.")
        use.status, use.approved_by, use.approved_at = "approved", approver, self.clock()
        self._record("approved", use, approver=approver)
        return use

    def change_risk_tier(self, use_id: str, new_tier: str, by: str) -> Use:
        use = self.uses[use_id]
        old = use.risk_tier
        use.risk_tier = new_tier
        use.status = "review"
        self._record("risk_tier_changed", use, by=by, old=old, new=new_tier)
        return use

    def disable_person(self, staff_id: str) -> list[str]:
        self.staff[staff_id]["active"] = False
        paused = []
        for use in self.uses.values():
            if use.owner == staff_id and use.status == "approved":
                use.status = "paused"
                paused.append(use.id)
                self._record("paused_owner_left", use, owner=staff_id)
        return paused

    def kill(self, use_id: str, by: str) -> Use:
        use = self.uses[use_id]
        use.status = "killed"
        self._record("killed", use, by=by)
        return use

    def refresh(self, use: Use) -> Use:
        """Expiry: an approval older than APPROVAL_DAYS lapses."""
        if use.status == "approved" and use.approved_at and self.clock() - use.approved_at > timedelta(days=APPROVAL_DAYS):
            use.status = "expired"
            self._record("expired", use)
        return use


    def recertify(self, use_id: str, approver: str) -> Use:
        """An expired use asks to be approved again, by someone other than its owner."""
        use = self.uses[use_id]
        if use.status != "expired":
            raise RegistryError("Only an expired use needs re-certification.")
        use.status = "draft"
        try:
            return self.approve(use_id, approver)
        except RegistryError:
            use.status = "expired"
            raise

    def snapshot(self) -> dict:
        """The register as it stands: used for the periodic review (E10)."""
        return {u.id: {"name": u.name, "owner": u.owner, "tier": u.risk_tier, "model": f"{u.model} {u.model_version}",
                       "status": u.status, "tools": sorted(u.tools)} for u in self.uses.values()}


def diff(old: dict, new: dict) -> dict:
    changed = {}
    for k in old.keys() & new.keys():
        delta = {f: (old[k][f], new[k][f]) for f in old[k] if old[k][f] != new[k][f]}
        if delta:
            changed[k] = delta
    return {"added": sorted(new.keys() - old.keys()), "removed": sorted(old.keys() - new.keys()), "changed": changed}
