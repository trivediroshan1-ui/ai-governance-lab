"""The detectors the lab can run its guardrail cases against.

v1        the plain filter from round one
v2        the round-two filter
external  any tool you wrap in a small command (see adapters/README.md)

Every detector has check(text) -> Result and check_session(messages) -> Result,
and a `supports` set saying which jobs it claims to do, so a tool is not marked
down for something it never promised (a PII library has no injection detector).
"""
from __future__ import annotations

import atexit
import json
import shlex
import subprocess

from . import guardrail, guardrail_v2, guardrail_v3
from .guardrail import Finding
from .guardrail_v2 import Result

ALL_JOBS = {"secrets", "personal", "injection"}


class Detector:
    def __init__(self, name, check, check_session=None, supports=None):
        self.name, self._check = name, check
        self._session = check_session
        self.supports = set(supports or ALL_JOBS)

    def check(self, text: str) -> Result:
        return self._check(text)

    def check_session(self, messages: list[str]) -> Result:
        if self._session:
            return self._session(messages)
        return self._check(messages[-1])  # no look-back: only the latest message


def _external(cmd: str) -> Detector:
    """Runs your command once and talks to it a line at a time: one JSON
    request per line in, one JSON answer per line out. A tool that is slow
    to start (it loads a model) pays that once, not for every text."""
    argv = shlex.split(cmd)
    info = json.loads(subprocess.run(argv + ["--info"], capture_output=True, text=True, check=True).stdout)
    proc = subprocess.Popen(argv + ["--serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
    atexit.register(proc.kill)

    def run(text: str) -> Result:
        proc.stdin.write(json.dumps({"text": text}) + "\n")
        proc.stdin.flush()
        data = json.loads(proc.stdout.readline())
        kinds = [Finding(k, "") for k in data.get("kinds", [])]
        return Result(masked=data.get("masked", text), findings=kinds, injection=bool(data.get("injection")))

    return Detector(info.get("name", "external"), run, supports=info.get("supports", ALL_JOBS))


def get(name: str) -> Detector:
    if name == "v1":
        return Detector("v1", guardrail.check)
    if name == "v2":
        return Detector("v2", guardrail_v2.check, guardrail_v2.check_session)
    if name == "v3":
        return Detector("v3", guardrail_v3.check, guardrail_v3.check_session)
    if name.startswith("external:"):
        return _external(name.split(":", 1)[1])
    raise SystemExit(f"unknown detector {name!r}: use v1, v2, v3 or external:<command>")
