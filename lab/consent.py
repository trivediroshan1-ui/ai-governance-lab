from __future__ import annotations
"""Third-party AI apps: what happens when a vendor says its AI "only needs read
access". Every app asks for scopes. A scope that covers the whole domain is
held until it is narrowed and a data owner is named. A narrower scope is
granted for 90 days, not for ever. A review finds expired grants and apps
nobody has used."""
from datetime import timedelta

from .hashlog import HashLog

HOME_REGION = "IN"
GRANT_DAYS = 90
UNUSED_DAYS = 30
# What each folder holds. Made up.
FOLDERS = {
    "/Shared/Support FAQ": "public",
    "/Shared/Marketing": "internal",
    "/HR/Salary review": "confidential",
    "/Customers/Loan files": "personal",
}
TENANT_WIDE = {"mail.read.all", "files.read.all", "domain.read"}


class Consents:
    def __init__(self, staff: list[dict], log: HashLog, clock):
        self.staff = {s["id"]: s for s in staff}
        self.log = log
        self.clock = clock
        self.grants: list[dict] = []

    def _record(self, action: str, **extra):
        self.log.append({"at": self.clock().isoformat(), "kind": "consent", "action": action, **extra})

    def request(self, app: str, vendor: str, scopes: list[str], region: str = "IN", data_owner: str | None = None) -> dict:
        wide = sorted(set(scopes) & TENANT_WIDE)
        if wide:
            self._record("held_tenant_wide", app=app, scopes=wide)
            return {"outcome": "held", "reason": f"tenant-wide scope {', '.join(wide)}: narrow it to named folders and name a data owner"}
        owner = self.staff.get(data_owner or "", {})
        if not owner.get("active"):
            self._record("held_no_owner", app=app)
            return {"outcome": "held", "reason": "no active data owner named"}
        classes = {FOLDERS.get(s.split(":", 1)[1], "unknown") for s in scopes if ":" in s}
        if "unknown" in classes:
            self._record("held_unknown_folder", app=app)
            return {"outcome": "held", "reason": "a folder is not in the data map"}
        if region != HOME_REGION and classes & {"confidential", "personal"}:
            self._record("held_cross_border", app=app, region=region, classes=sorted(classes))
            return {"outcome": "held", "reason": f"app processes in {region}; folders hold {', '.join(sorted(classes & {'confidential', 'personal'}))} data"}
        now = self.clock()
        g = {"app": app, "vendor": vendor, "scopes": list(scopes), "owner": data_owner, "region": region,
             "granted": now, "expires": now + timedelta(days=GRANT_DAYS), "last_used": None, "revoked": False}
        self.grants.append(g)
        self._record("granted", app=app, scopes=list(scopes), owner=data_owner, expires=g["expires"].isoformat())
        return {"outcome": "granted", "reason": f"granted for {GRANT_DAYS} days", "expires": g["expires"].isoformat()}

    def use(self, app: str, scope: str) -> bool:
        now = self.clock()
        for g in self.grants:
            if g["app"] == app and not g["revoked"] and g["expires"] > now and scope in g["scopes"]:
                g["last_used"] = now
                return True
        return False

    def review(self) -> dict:
        now = self.clock()
        expired = sorted(g["app"] for g in self.grants if g["expires"] <= now and not g["revoked"])
        for g in self.grants:
            if g["expires"] <= now:
                g["revoked"] = True
        unused = sorted(g["app"] for g in self.grants
                        if not g["revoked"] and now - (g["last_used"] or g["granted"]) > timedelta(days=UNUSED_DAYS))
        self._record("review", expired=expired, unused=unused)
        return {"expired": expired, "unused": unused}
