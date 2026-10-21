from __future__ import annotations
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
    def __init__(self, registry: Registry, log: HashLog, clock, screen=None):
        self.screen = screen or guardrail.check       # the guardrail filter; cases can swap it
        self.down: set[str] = set()                   # models that are currently unavailable
        self.registry = registry
        self.log = log
        self.clock = clock
        self.tickets: list[dict] = []
        self.seen_callers: set[tuple[str, str]] = set()   # (caller, model) pairs, for discovery

    def _decide(self, req: Request, outcome: str, reason: str, model_used: str | None = None, **extra) -> Decision:
        self.log.append({"at": self.clock().isoformat(), "kind": "gateway", "use": req.use_id,
                         "caller": req.caller, "model": model_used or req.model, "outcome": outcome, "reason": reason})
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
        model_name, fallback = req.model, False
        if req.model == use.model and req.model in self.down:
            if not use.fallback_model:
                return self._decide(req, "blocked", "model unavailable and no fallback registered")
            model_name, fallback = use.fallback_model, True
            self.log.append({"at": self.clock().isoformat(), "kind": "gateway", "action": "fallback_used",
                             "use": use.id, "from": req.model, "to": model_name})
        if not fallback and req.model != use.model:
            return self._decide(req, "blocked", "model not approved for this use")
        if not fallback and req.model_version != use.model_version:
            use.status = "review"
            self.registry._record("version_changed", use, approved=use.model_version, seen=req.model_version)
            return self._decide(req, "held", "model version changed since approval; re-review needed")
        if use.aibom is None:
            return self._decide(req, "held", "no AI bill of materials on file")
        extra_tools = sorted(set(req.tools) - set(use.tools))
        if extra_tools:
            return self._decide(req, "blocked", f"tools not registered for this use: {', '.join(extra_tools)}")

        model = self.registry.models[model_name]
        if model.review is None:
            return self._decide(req, "held", "no model and supplier review on file", model_used=model_name)
        scan = self.screen(req.prompt)
        classes = set(req.labels) | ({"personal"} if scan.personal else set())
        if classes - set(use.data_classes):
            return self._decide(req, "blocked", f"data not allowed for this use: {', '.join(sorted(classes - set(use.data_classes)))}", model_used=model_name)
        if classes - set(model.allowed_data):
            return self._decide(req, "blocked", f"model not approved for: {', '.join(sorted(classes - set(model.allowed_data)))}", model_used=model_name)
        if model.region != HOME_REGION and classes & {"confidential", "personal"}:
            return self._decide(req, "held", f"cross-border: {model.region} model with {', '.join(sorted(classes))} data", model_used=model_name)
        if scan.injection:
            return self._decide(req, "blocked", "possible prompt injection", model_used=model_name)
        return self._decide(req, "allowed", "within the register" + (" (fallback model)" if fallback else ""),
                            model_used=model_name, sent_prompt=scan.masked)

    def screen_response(self, use_id: str, text: str) -> tuple[str, list[str]]:
        """Checks what comes back from the model before it goes to the user (G10)."""
        r = self.screen(text)
        if r.findings:
            self.log.append({"at": self.clock().isoformat(), "kind": "gateway", "action": "output_masked",
                             "use": use_id, "found": sorted(r.kinds)})
        return r.masked, sorted(r.kinds)

    def deliver(self, use_id: str, text: str) -> str:
        """What the person actually sees. Customer-facing uses add their AI notice (E8)."""
        use = self.registry.uses[use_id]
        return f"{text}\n\n{use.notice}" if use.audience == "customer" and use.notice else text

    def discovery_gap(self) -> dict:
        """What the gateway saw being called versus what is registered (E1)."""
        registered = {(u.name, u.model) for u in self.registry.uses.values()}
        seen = self.seen_callers
        unregistered = sorted(c for c in seen if c not in registered)
        return {"seen": len(seen), "registered": len(registered), "unregistered": unregistered}
