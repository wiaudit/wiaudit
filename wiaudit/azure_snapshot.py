"""Load and save the Azure snapshot (our own JSON format, produced by `wiaudit collect azure`).

Format (version 1):
{
  "version": 1,
  "tenantId": "...",
  "collectedAt": "2026-11-22T10:00:00Z",
  "identities": [
    {
      "kind": "app" | "managedIdentity",
      "displayName": "...",
      "clientId": "...",            # appId for apps
      "objectId": "...",            # service principal / MI principal id
      "resourceId": "...",          # MI only
      "federatedCredentials": [
        {"name": "...", "issuer": "...", "subject": "..." | null,
         "audiences": ["api://AzureADTokenExchange"],
         "claimsMatchingExpression": "..." | null}
      ],
      "roleAssignments": [{"role": "Contributor", "scope": "/subscriptions/..."}]
    }
  ]
}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import AzureSnapshot, FederatedCredential, Identity, RepoInfo, RoleAssignment


def _expr_value(raw: Any) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, dict):  # Graph returns {"value": "...", "languageVersion": 1}
        return raw.get("value")
    return str(raw)


def snapshot_from_dict(data: dict[str, Any]) -> AzureSnapshot:
    identities = []
    for raw in data.get("identities", []):
        identities.append(
            Identity(
                kind=raw.get("kind", "app"),
                display_name=raw.get("displayName") or raw.get("name") or "?",
                client_id=raw.get("clientId") or raw.get("appId") or "?",
                object_id=raw.get("objectId"),
                resource_id=raw.get("resourceId"),
                federated_credentials=[
                    FederatedCredential(
                        name=f.get("name", "?"),
                        issuer=f.get("issuer", ""),
                        subject=f.get("subject"),
                        audiences=list(f.get("audiences") or []),
                        claims_matching_expression=_expr_value(f.get("claimsMatchingExpression")),
                    )
                    for f in raw.get("federatedCredentials", [])
                ],
                role_assignments=[
                    RoleAssignment(
                        role=r.get("role") or r.get("roleDefinitionName") or "?",
                        scope=r.get("scope", ""),
                    )
                    for r in raw.get("roleAssignments", [])
                ],
            )
        )
    return AzureSnapshot(
        tenant_id=data.get("tenantId"),
        identities=identities,
        collected_at=data.get("collectedAt"),
    )


def load_snapshot(path: str | Path) -> AzureSnapshot:
    with open(path, encoding="utf-8") as fh:
        return snapshot_from_dict(json.load(fh))


def save_json(data: dict[str, Any] | list[Any], path: str | Path) -> None:
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def load_repo_inventory(path: str | Path) -> dict[str, RepoInfo]:
    """repos.json produced by `wiaudit collect github` (or written by hand).

    [{"fullName": "org/repo", "ownerId": "123", "repoId": "456",
      "createdAt": "2026-08-01T..", "usesImmutable": null, "exists": true}]
    """
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    out: dict[str, RepoInfo] = {}
    for r in raw:
        if r.get("exists") is False:
            continue
        info = RepoInfo(
            full_name=r["fullName"],
            owner_id=str(r["ownerId"]) if r.get("ownerId") is not None else None,
            repo_id=str(r["repoId"]) if r.get("repoId") is not None else None,
            created_at=r.get("createdAt"),
            uses_immutable=r.get("usesImmutable"),
        )
        out[info.full_name.lower()] = info
    return out


def load_missing_repos(path: str | Path) -> set[str]:
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    return {r["fullName"].lower() for r in raw if r.get("exists") is False}
