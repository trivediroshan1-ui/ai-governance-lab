from __future__ import annotations
"""An agent's memory. Two defences against a poisoned note (OWASP ASI06):

1. Provenance. A note that came from a document, web page or email is
   untrusted. It is handed back as quoted data, never as an instruction.
2. Content. Every note is checked for instruction-like text when it is read
   back, and flagged ones are held out.

Provenance does not help when the attacker writes through a trusted route
(for example, text the user pasted in themselves), so the content check
still matters, and it is only as good as the filter behind it.
"""
UNTRUSTED = {"document", "web", "email"}


class AgentMemory:
    def __init__(self, agent_id: str, log, clock, screen):
        self.agent_id, self.log, self.clock, self.screen = agent_id, log, clock, screen
        self.notes: list[dict] = []

    def write(self, text: str, source: str) -> None:
        self.notes.append({"text": text, "source": source, "at": self.clock().isoformat()})
        self.log.append({"at": self.clock().isoformat(), "kind": "memory", "action": "written",
                         "agent": self.agent_id, "source": source})

    def read(self) -> dict:
        """What the agent is allowed to see on its next run."""
        instructions, data, flagged = [], [], []
        for n in self.notes:
            if self.screen(n["text"]).injection:
                flagged.append(n)
                self.log.append({"at": self.clock().isoformat(), "kind": "memory", "action": "flagged_on_read",
                                 "agent": self.agent_id, "source": n["source"]})
            elif n["source"] in UNTRUSTED:
                data.append({"quoted": n["text"], "trust": "untrusted: data, not instructions"})
            else:
                instructions.append(n["text"])
        return {"instructions": instructions, "data": data, "flagged": flagged}
