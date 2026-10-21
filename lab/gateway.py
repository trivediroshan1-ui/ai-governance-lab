"""The AI use gateway: every call to a model goes through here. It checks the
register, the model, the data, where the model runs and which tools are
asked for, masks what the guardrail finds, and writes every decision to the
hash-chain log."""
from dataclasses import dataclass, field

from . import guardrail
from .hashlog import HashLog
from .registry import Registry

HOME_REGION = "IN"


@dataclass
class Request:
    use_id: str | None
    model: str
    model_version: str
    prompt: str
    labels: list[str] = field(default_factory=list)   # what the sender says the data is, e.g. "confidential"
    tools: list[str] = field(default_factory=list)
    caller: str = "app"                                 # the app or team making the call


@dataclass
class Decision:
    outcome: str            # allowed, blocked, held
    reason: str
    sent_prompt: str | None = None
    ticket: str | None = None


class Gateway:
    def __init__(self, registry: Registry, log: HashLog, clock):
        self.registry = registry
        self.log = log
        self.clock = clock
        self.tickets: list[dict] = []
        self.seen_callers: set[tuple[str, str]] = set()   # (caller, model) pairs, for discovery

    def _decide(self, req: Request, outcome: str, reason: str, **extra) -> Decision:
        self.log.append({"at": self.clock().isoformat(), "kind": "gateway", "use": req.use_id,
                         "caller": req.caller, "model": req.model, "outcome": outcome, "reason": reason})
        return Decision(outcome, reason, **extra)

    def handle(self, req: Request) -> Decision:
        self.seen_callers.add((req.caller, req.model))
        use = self.registry.uses.get(req.use_id or "")
        if use is None:
            ticket = f"DISC-{len(self.tickets) + 1:03d}"
            self.tickets.append({"id": ticket, "caller": req.caller, "model": req.model, "at": self.clock().isoformat()})
            return self._decide(req, "blocked", "not in the AI use register", ticket=ticket)

        self.registry.refresh(use)
        if use.status != "approved":
            return self._decide(req, "blocked", f"use is {use.status}")
        if req.model != use.model:
            return self._decide(req, "blocked", "model not approved for this use")
        if req.model_version != use.model_version:
            use.status = "review"
            self.registry._record("version_changed", use, approved=use.model_version, seen=req.model_version)
            return self._decide(req, "held", "model version changed since approval; re-review needed")
        if use.aibom is None:
            return self._decide(req, "held", "no AI bill of materials on file")
        extra_tools = sorted(set(req.tools) - set(use.tools))
        if extra_tools:
            return self._decide(req, "blocked", f"tools not registered for this use: {', '.join(extra_tools)}")

        scan = guardrail.check(req.prompt)
        model = self.registry.models[req.model]
        classes = set(req.labels) | ({"personal"} if scan.personal else set())
        if classes - set(use.data_classes):
            return self._decide(req, "blocked", f"data not allowed for this use: {', '.join(sorted(classes - set(use.data_classes)))}")
        if classes - set(model.allowed_data):
            return self._decide(req, "blocked", f"model not approved for: {', '.join(sorted(classes - set(model.allowed_data)))}")
        if model.region != HOME_REGION and classes & {"confidential", "personal"}:
            return self._decide(req, "held", f"cross-border: {model.region} model with {', '.join(sorted(classes))} data")
        if scan.injection:
            return self._decide(req, "blocked", "possible prompt injection")
        return self._decide(req, "allowed", "within the register", sent_prompt=scan.masked)

    def discovery_gap(self) -> dict:
        """What the gateway saw being called versus what is registered (E1)."""
        registered = {(u.name, u.model) for u in self.registry.uses.values()}
        seen = self.seen_callers
        unregistered = sorted(c for c in seen if c not in registered)
        return {"seen": len(seen), "registered": len(registered), "unregistered": unregistered}
