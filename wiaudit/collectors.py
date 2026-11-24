"""Read-only collectors that shell out to the official CLIs (az, gh).

Nothing here writes to Azure or GitHub. Every call is a GET / list.
The user's own login is used; credentials never pass through wiaudit.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Callable

from .models import GITHUB_ISSUER
from .subjects import flexible_sub_patterns, parse_subject

Runner = Callable[[list[str]], Any]


class CollectorError(RuntimeError):
    pass


def _resolve_command(args: list[str]) -> list[str]:
    """Return the argv to execute.

    On Windows `az` is a batch file (az.cmd). Running it sends every argument through
    cmd.exe, which treats `&` in Graph URLs (`?$select=...&$top=999`) as a command
    separator. So we call the Python that ships with Azure CLI directly, exactly as
    az.cmd itself does (`python.exe -IBm azure.cli ...`), and no shell is involved.
    """
    exe = shutil.which(args[0])
    if not exe:
        raise CollectorError(f"'{args[0]}' not found on PATH. Install it and log in first.")
    if os.name == "nt" and exe.lower().endswith((".cmd", ".bat")):
        if args[0] == "az":
            cli_root = os.path.dirname(os.path.dirname(exe))  # ...\CLI2\wbin\az.cmd -> ...\CLI2
            bundled = os.path.join(cli_root, "python.exe")
            if os.path.isfile(bundled):
                return [bundled, "-IBm", "azure.cli", *args[1:]]
        if any(ch in a for a in args[1:] for ch in "&|<>^%"):
            raise CollectorError(
                f"{exe} is a batch file and an argument contains characters cmd.exe would misread. "
                "Please report this at https://github.com/wiaudit/wiaudit/issues"
            )
    return [exe, *args[1:]]


def _default_runner(args: list[str]) -> Any:
    argv = _resolve_command(args)
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=180)
    if proc.returncode != 0:
        raise CollectorError(f"{' '.join(args[:4])}... failed: {proc.stderr.strip()[:500]}")
    out = proc.stdout.strip()
    return json.loads(out) if out else None


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


# --------------------------------------------------------------------- Azure


def _graph_get_all(run: Runner, url: str, advanced: bool = False) -> list[dict[str, Any]]:
    """GET all pages. advanced=True adds ConsistencyLevel: eventual (Graph advanced queries)."""
    items: list[dict[str, Any]] = []
    extra = ["--headers", "ConsistencyLevel=eventual"] if advanced else []
    while url:
        page = run(["az", "rest", "--method", "GET", "--url", url, *extra, "-o", "json"]) or {}
        items.extend(page.get("value", []))
        url = page.get("@odata.nextLink")
    return items


GRAPH = "https://graph.microsoft.com/v1.0"


def _list_apps(run: Runner, all_issuers: bool) -> list[dict[str, Any]]:
    """Apps to inspect. By default only apps that trust the GitHub issuer, filtered server-side,
    so large tenants (thousands of apps) take seconds instead of hours."""
    select = "$select=id,appId,displayName&$top=999"
    if not all_issuers:
        flt = f"federatedIdentityCredentials/any(f:f/issuer eq '{GITHUB_ISSUER}')".replace(" ", "%20")
        _log("[azure] app registrations trusting GitHub Actions (Microsoft Graph)")
        try:
            return _graph_get_all(run, f"{GRAPH}/applications?$filter={flt}&$count=true&{select}", advanced=True)
        except CollectorError as exc:
            _log(f"[azure] filtered query not available ({str(exc)[:120]}); falling back to listing all apps")
    _log("[azure] all app registrations (Microsoft Graph) - this can take long in large tenants")
    return _graph_get_all(run, f"{GRAPH}/applications?{select}")


def collect_azure(
    subscriptions: list[str] | None = None,
    all_subscriptions: bool = False,
    app_name_prefix: str | None = None,
    include_apps: bool = True,
    include_managed_identities: bool = True,
    all_issuers: bool = False,
    run: Runner = _default_runner,
) -> dict[str, Any]:
    account = run(["az", "account", "show", "-o", "json"]) or {}
    tenant_id = account.get("tenantId")
    if all_subscriptions:
        subs = [s["id"] for s in run(["az", "account", "list", "-o", "json"]) or [] if s.get("tenantId") == tenant_id]
    else:
        subs = subscriptions or [account.get("id")]
    subs = [s for s in subs if s]

    identities: list[dict[str, Any]] = []

    if include_managed_identities:
        for sub in subs:
            _log(f"[azure] managed identities in subscription {sub}")
            for mi in run(["az", "identity", "list", "--subscription", sub, "-o", "json"]) or []:
                fics = run(
                    [
                        "az", "identity", "federated-credential", "list",
                        "--identity-name", mi["name"],
                        "--resource-group", mi["resourceGroup"],
                        "--subscription", sub, "-o", "json",
                    ]
                ) or []
                if not fics:
                    continue
                identities.append(
                    {
                        "kind": "managedIdentity",
                        "displayName": mi["name"],
                        "clientId": mi.get("clientId"),
                        "objectId": mi.get("principalId"),
                        "resourceId": mi.get("id"),
                        "federatedCredentials": [_fic(f) for f in fics],
                    }
                )

    if include_apps:
        apps = _list_apps(run, all_issuers)
        if app_name_prefix:
            apps = [a for a in apps if (a.get("displayName") or "").startswith(app_name_prefix)]
        _log(f"[azure] {len(apps)} app registrations to inspect")
        for i, app in enumerate(apps, 1):
            if i % 25 == 0 or i == len(apps):
                _log(f"[azure]   {i}/{len(apps)}")
            try:  # beta exposes claimsMatchingExpression (flexible credentials)
                fics = _graph_get_all(
                    run, f"https://graph.microsoft.com/beta/applications/{app['id']}/federatedIdentityCredentials"
                )
            except CollectorError:
                fics = _graph_get_all(
                    run, f"https://graph.microsoft.com/v1.0/applications/{app['id']}/federatedIdentityCredentials"
                )
            if not fics:
                continue
            sp = None
            try:
                sp = run(
                    [
                        "az", "rest", "--method", "GET", "--url",
                        f"https://graph.microsoft.com/v1.0/servicePrincipals(appId='{app['appId']}')?$select=id",
                        "-o", "json",
                    ]
                )
            except CollectorError:
                pass
            identities.append(
                {
                    "kind": "app",
                    "displayName": app.get("displayName"),
                    "clientId": app.get("appId"),
                    "objectId": (sp or {}).get("id"),
                    "federatedCredentials": [_fic(f) for f in fics],
                }
            )

    for ident in identities:
        ident["roleAssignments"] = []
        if not ident.get("objectId"):
            continue
        for sub in subs:
            ras = run(
                [
                    "az", "role", "assignment", "list",
                    "--assignee-object-id", ident["objectId"],
                    "--all", "--include-inherited",
                    "--subscription", sub, "-o", "json",
                ]
            ) or []
            for ra in ras:
                entry = {"role": ra.get("roleDefinitionName"), "scope": ra.get("scope")}
                if entry not in ident["roleAssignments"]:
                    ident["roleAssignments"].append(entry)

    return {
        "version": 1,
        "tenantId": tenant_id,
        "collectedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "subscriptions": subs,
        "identities": identities,
    }


def _fic(raw: dict[str, Any]) -> dict[str, Any]:
    expr = raw.get("claimsMatchingExpression")
    if isinstance(expr, dict):
        expr = expr.get("value")
    return {
        "name": raw.get("name"),
        "issuer": raw.get("issuer"),
        "subject": raw.get("subject"),
        "audiences": raw.get("audiences") or [],
        "claimsMatchingExpression": expr,
    }


# -------------------------------------------------------------------- GitHub


def repos_referenced_by_snapshot(snapshot: dict[str, Any]) -> list[str]:
    names: set[str] = set()
    for ident in snapshot.get("identities", []):
        for f in ident.get("federatedCredentials", []):
            if (f.get("issuer") or "").rstrip("/") != GITHUB_ISSUER:
                continue
            subjects = [f.get("subject")] + [v for _op, v in flexible_sub_patterns(f.get("claimsMatchingExpression") or "")]
            for s in subjects:
                p = parse_subject(s)
                if p and "*" not in p.full_name and "?" not in p.full_name:
                    names.add(p.full_name)
    return sorted(names)


def collect_github(repos: list[str], run: Runner = _default_runner) -> list[dict[str, Any]]:
    """Fetch ids and creation dates; mark repos that no longer exist (dangling trust)."""
    out = []
    for full in repos:
        _log(f"[github] {full}")
        try:
            data = run(["gh", "api", f"repos/{full}"]) or {}
        except CollectorError as exc:
            if "404" in str(exc) or "Not Found" in str(exc):
                out.append({"fullName": full, "exists": False})
                continue
            raise
        out.append(
            {
                "fullName": data.get("full_name", full),
                "ownerId": (data.get("owner") or {}).get("id"),
                "repoId": data.get("id"),
                "createdAt": data.get("created_at"),
                "usesImmutable": None,
                "exists": True,
                "renamedFrom": full if data.get("full_name", full).lower() != full.lower() else None,
            }
        )
    return out
