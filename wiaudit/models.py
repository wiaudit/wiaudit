"""Plain data structures shared by collectors, rules and reports."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any

GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
AZURE_DEFAULT_AUDIENCE = "api://AzureADTokenExchange"
# GitHub applies the immutable subject format to repos created, renamed or
# transferred on or after this date (github.blog changelog 2026-04-23).
IMMUTABLE_SUBJECT_CUTOFF = "2026-07-15"
# Entra limit of federated identity credentials per app or user-assigned MI.
FIC_LIMIT = 20

PRIVILEGED_ROLES = {
    "owner": 3,
    "user access administrator": 3,
    "role based access control administrator": 3,
    "contributor": 2,
}


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> "Severity":
        return cls[value.strip().upper()]


# ---------------------------------------------------------------- Azure side


@dataclass
class FederatedCredential:
    name: str
    issuer: str
    subject: str | None
    audiences: list[str] = field(default_factory=list)
    claims_matching_expression: str | None = None

    @property
    def is_github(self) -> bool:
        return self.issuer.rstrip("/") == GITHUB_ISSUER

    @property
    def is_flexible(self) -> bool:
        return bool(self.claims_matching_expression)


@dataclass
class RoleAssignment:
    role: str
    scope: str

    @property
    def scope_level(self) -> str:
        s = self.scope.lower().rstrip("/")
        if s in ("", "/"):
            return "root"
        if "/providers/microsoft.management/managementgroups/" in s:
            return "managementGroup"
        parts = s.split("/")
        # /subscriptions/<id>
        if len(parts) == 3 and parts[1] == "subscriptions":
            return "subscription"
        if len(parts) == 5 and parts[3] == "resourcegroups":
            return "resourceGroup"
        return "resource"

    @property
    def privilege(self) -> int:
        """0 = not privileged, 2 = write everything, 3 = can grant access."""
        return PRIVILEGED_ROLES.get(self.role.lower(), 0)


@dataclass
class Identity:
    kind: str  # "app" or "managedIdentity"
    display_name: str
    client_id: str
    object_id: str | None = None
    resource_id: str | None = None
    federated_credentials: list[FederatedCredential] = field(default_factory=list)
    role_assignments: list[RoleAssignment] = field(default_factory=list)

    @property
    def ref(self) -> str:
        return f"{self.kind}:{self.display_name} ({self.client_id})"

    @property
    def max_privilege(self) -> int:
        """Highest privilege, counting only broad scopes (subscription or above)."""
        best = 0
        for ra in self.role_assignments:
            if ra.scope_level in ("root", "managementGroup", "subscription"):
                best = max(best, ra.privilege)
        return best

    def privileged_assignments(self) -> list[RoleAssignment]:
        return [
            ra
            for ra in self.role_assignments
            if ra.privilege and ra.scope_level in ("root", "managementGroup", "subscription")
        ]


@dataclass
class AzureSnapshot:
    tenant_id: str | None
    identities: list[Identity]
    collected_at: str | None = None


# --------------------------------------------------------------- GitHub side


@dataclass
class RepoInfo:
    """Optional GitHub metadata used to compute immutable subjects."""

    full_name: str  # owner/repo
    owner_id: str | None = None
    repo_id: str | None = None
    created_at: str | None = None  # ISO date
    uses_immutable: bool | None = None  # explicit opt-in / known state
    owner_type: str | None = None  # "Organization" | "User" (from GitHub API)

    @property
    def owner(self) -> str:
        return self.full_name.split("/", 1)[0]

    @property
    def name(self) -> str:
        return self.full_name.split("/", 1)[1]

    def expects_immutable(self) -> bool | None:
        if self.uses_immutable is not None:
            return self.uses_immutable
        if self.created_at:
            return self.created_at[:10] >= IMMUTABLE_SUBJECT_CUTOFF
        return None


@dataclass
class LoginStep:
    uses: str
    client_id: str | None  # literal value, or expression like ${{ secrets.X }}
    uses_oidc: bool
    uses_secret_creds: bool
    line: int | None = None


@dataclass
class Job:
    job_id: str
    environment: str | None
    permissions: dict[str, str] | str | None  # None = key absent
    login_steps: list[LoginStep] = field(default_factory=list)
    line: int | None = None


@dataclass
class Workflow:
    path: str  # path relative to repo root
    name: str | None
    triggers: dict[str, Any]
    permissions: dict[str, str] | str | None
    jobs: list[Job] = field(default_factory=list)


# ----------------------------------------------------------------- Findings


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    message: str
    remediation: str
    target: str  # identity ref or workflow path
    location: str | None = None  # file path for SARIF
    line: int | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        return d
