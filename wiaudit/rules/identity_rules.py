"""Rules that look at Entra / Azure identities and their federated credentials."""

from __future__ import annotations

from typing import Iterable

from ..models import (
    AZURE_DEFAULT_AUDIENCE,
    FIC_LIMIT,
    AzureSnapshot,
    FederatedCredential,
    Finding,
    Identity,
    RepoInfo,
    Severity,
)
from ..subjects import (
    flexible_binds_immutable_claim,
    flexible_sub_patterns,
    parse_subject,
    repo_prefix,
)

KNOWN_ISSUER_PREFIXES = (
    "https://token.actions.githubusercontent.com",
    "https://gitlab.com",
    "https://app.terraform.io",
    "https://vstoken.dev.azure.com",
    "https://login.microsoftonline.com",
    "https://sts.windows.net",
    "https://oidc.prod-aks.azure.com",  # AKS workload identity
    "https://accounts.google.com",
)


def _privilege_bump(identity: Identity, base: Severity) -> Severity:
    p = identity.max_privilege
    if p >= 3:
        return Severity(min(Severity.CRITICAL, base + 2))
    if p == 2:
        return Severity(min(Severity.CRITICAL, base + 1))
    return base


def _priv_text(identity: Identity) -> str:
    pa = identity.privileged_assignments()
    if not pa:
        return "no broad privileged roles found"
    return ", ".join(f"{ra.role} on {ra.scope_level} {ra.scope}" for ra in pa[:3])


def _subjects_of(fic: FederatedCredential) -> list[str]:
    if fic.subject and not fic.is_flexible:
        return [fic.subject]
    return [v for _op, v in flexible_sub_patterns(fic.claims_matching_expression or "")]


def check_identity(
    identity: Identity,
    inventory: dict[str, RepoInfo] | None = None,
    missing_repos: set[str] | None = None,
    renamed: dict[str, str] | None = None,
) -> Iterable[Finding]:
    inventory = inventory or {}
    missing_repos = missing_repos or set()
    renamed = renamed or {}
    target = identity.ref

    # WIA004: broad privileged roles (independent of credentials)
    for ra in identity.privileged_assignments():
        sev = Severity.HIGH if ra.privilege >= 3 else Severity.MEDIUM
        yield Finding(
            rule_id="WIA004",
            severity=sev,
            title="Federated identity holds broad privileged role",
            message=f"{identity.display_name} has '{ra.role}' at {ra.scope_level} scope ({ra.scope}). "
            "Anyone who can satisfy one of its federated credentials gets this access.",
            remediation="Scope the role to the resource group or resources the pipeline deploys to. "
            "Avoid Owner / User Access Administrator for CI identities; use separate identities per environment.",
            target=target,
            details={"role": ra.role, "scope": ra.scope},
        )

    # WIA008: near the 20-credential limit
    if len(identity.federated_credentials) >= FIC_LIMIT - 2:
        yield Finding(
            rule_id="WIA008",
            severity=Severity.INFO,
            title="Identity close to the federated credential limit",
            message=f"{identity.display_name} has {len(identity.federated_credentials)} of {FIC_LIMIT} federated credentials.",
            remediation="Split identities per environment or use flexible federated credentials that bind repository_id.",
            target=target,
        )

    for fic in identity.federated_credentials:
        loc = f"{target} / credential '{fic.name}'"

        if not fic.is_github:
            if not any(fic.issuer.startswith(p) for p in KNOWN_ISSUER_PREFIXES):
                yield Finding(
                    rule_id="WIA009",
                    severity=Severity.LOW,
                    title="Federated credential from an unrecognized issuer",
                    message=f"Credential '{fic.name}' trusts issuer {fic.issuer}.",
                    remediation="Confirm the issuer is owned by your organization and still in use; delete it otherwise.",
                    target=loc,
                    details={"issuer": fic.issuer},
                )
            continue

        # WIA005: audience
        if fic.audiences and fic.audiences != [AZURE_DEFAULT_AUDIENCE]:
            yield Finding(
                rule_id="WIA005",
                severity=Severity.LOW,
                title="Non-default audience on federated credential",
                message=f"Credential '{fic.name}' accepts audiences {fic.audiences} instead of {AZURE_DEFAULT_AUDIENCE}.",
                remediation=f"Use the recommended audience {AZURE_DEFAULT_AUDIENCE} unless you have a documented reason.",
                target=loc,
                details={"audiences": fic.audiences},
            )

        # WIA002: flexible credential with wildcard but no immutable claim binding
        if fic.is_flexible:
            pats = flexible_sub_patterns(fic.claims_matching_expression or "")
            wildcard = any(op == "matches" and any(c in v for c in "*?") for op, v in pats)
            if wildcard and not flexible_binds_immutable_claim(fic.claims_matching_expression or ""):
                yield Finding(
                    rule_id="WIA002",
                    severity=_privilege_bump(identity, Severity.HIGH),
                    title="Flexible credential uses wildcards without binding repository_id",
                    message=f"Credential '{fic.name}' matches sub with a wildcard ({fic.claims_matching_expression}) "
                    "but does not check repository_id or repository_owner_id.",
                    remediation="Add `and claims['repository_id'] eq '<id>'` (and/or repository_owner_id) to the expression, "
                    "as Microsoft now requires for GitHub flexible credentials.",
                    target=loc,
                    details={"expression": fic.claims_matching_expression},
                )

        for subject in _subjects_of(fic):
            parsed = parse_subject(subject)
            if not parsed:
                continue
            key = parsed.full_name.lower()

            # WIA006 / WIA007: dangling trust
            if key in missing_repos:
                yield Finding(
                    rule_id="WIA006",
                    severity=_privilege_bump(identity, Severity.HIGH),
                    title="Trust points to a GitHub repository that no longer exists",
                    message=f"Credential '{fic.name}' trusts {parsed.full_name}, which GitHub reports as not found. "
                    "If the name is re-registered by someone else, their workflows can get this identity's token "
                    "(name-based subject).",
                    remediation="Delete the credential, or move it to the immutable subject format bound to the original IDs.",
                    target=loc,
                    details={"subject": subject},
                )
            elif key in renamed:
                yield Finding(
                    rule_id="WIA007",
                    severity=_privilege_bump(identity, Severity.MEDIUM),
                    title="Trust points to a renamed GitHub repository",
                    message=f"Credential '{fic.name}' trusts the old name {parsed.full_name}; the repo is now {renamed[key]}. "
                    "The old name can be registered again by someone else.",
                    remediation=f"Replace it with a credential for {renamed[key]} in the immutable subject format.",
                    target=loc,
                    details={"subject": subject, "newName": renamed[key]},
                )

            # WIA001: mutable subject (skip when a more specific finding already covers it)
            already_covered = fic.is_flexible or key in missing_repos or key in renamed
            if not parsed.is_immutable and not already_covered:
                info = inventory.get(key)
                suggestion = ""
                if info and info.owner_id and info.repo_id:
                    suggestion = f" Suggested subject: {repo_prefix(info, True)}:{parsed.context}"
                yield Finding(
                    rule_id="WIA001",
                    severity=_privilege_bump(identity, Severity.LOW),
                    title="GitHub trust uses a mutable, name-based subject",
                    message=f"Credential '{fic.name}' trusts '{subject}'. Name-based subjects follow renames and "
                    "recycled names; GitHub uses the immutable format for repos created, renamed or transferred "
                    "since 2026-07-15 and Microsoft recommends migrating.",
                    remediation="Migrate to repo:OWNER@OWNER_ID/REPO@REPO_ID:<context>, or a flexible credential that "
                    "also checks repository_id." + suggestion,
                    target=loc,
                    details={"subject": subject, "privileges": _priv_text(identity)},
                )

            # WIA003: pull_request trust
            if parsed.context_kind == "pull_request":
                yield Finding(
                    rule_id="WIA003",
                    severity=_privilege_bump(identity, Severity.MEDIUM),
                    title="Identity trusts pull_request workflows",
                    message=f"Credential '{fic.name}' accepts tokens from any pull_request run in {parsed.full_name}. "
                    "Anyone who can open a PR from a branch in the repo can act as this identity "
                    f"({_priv_text(identity)}).",
                    remediation="Use a separate low-privilege identity for PR validation (e.g. Reader / plan-only), "
                    "and environment-based subjects with required reviewers for deployments.",
                    target=loc,
                    details={"subject": subject},
                )


def _owner_of(subject: str) -> str | None:
    parsed = parse_subject(subject)
    if not parsed or "/" not in parsed.full_name:
        return None
    owner = parsed.full_name.split("/", 1)[0]
    return None if any(c in owner for c in "*?") else owner


def check_owners(
    snapshot: AzureSnapshot,
    inventory: dict[str, RepoInfo] | None = None,
    allowed_owners: set[str] | None = None,
) -> Iterable[Finding]:
    """WIA010 / WIA011: which GitHub owners (orgs or personal accounts) can get tokens in this tenant."""
    inventory = inventory or {}
    allowed = {o.lower() for o in allowed_owners} if allowed_owners else None
    counts: dict[str, int] = {}
    for identity in snapshot.identities:
        for fic in identity.federated_credentials:
            if not fic.is_github:
                continue
            for subject in _subjects_of(fic):
                owner = _owner_of(subject)
                if not owner:
                    continue
                counts[owner] = counts.get(owner, 0) + 1
                parsed = parse_subject(subject)
                repo = inventory.get(parsed.full_name.lower()) if parsed else None
                reason = None
                if allowed is not None and owner.lower() not in allowed:
                    reason = f"owner '{owner}' is not in your allowed GitHub owners"
                elif repo and (repo.owner_type or "").lower() == "user":
                    reason = f"'{owner}' is a personal GitHub account, not an organization"
                if not reason:
                    continue
                yield Finding(
                    rule_id="WIA010",
                    severity=_privilege_bump(identity, Severity.MEDIUM),
                    title="Trust to a GitHub repository outside your organizations",
                    message=f"Credential '{fic.name}' trusts {parsed.full_name if parsed else subject}: {reason}. "
                    "Personal and external accounts are outside your org's SSO, policies and offboarding; "
                    f"whoever controls that repo can act as this identity ({_priv_text(identity)}).",
                    remediation="Move the repository into your GitHub organization, or delete the credential. "
                    "If the trust is intended, document it and add the owner to --allowed-owners.",
                    target=f"{identity.ref} / credential '{fic.name}'",
                    details={"owner": owner},
                )
    if allowed is None and len(counts) > 1:
        listing = ", ".join(f"{o} ({n})" for o, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0].lower())))
        yield Finding(
            rule_id="WIA011",
            severity=Severity.INFO,
            title="GitHub owners trusted in this tenant (review list)",
            message=f"Federated credentials trust repositories from {len(counts)} GitHub owners: {listing}.",
            remediation="Check that every owner is one of your organizations. Rerun with "
            "--allowed-owners org1,org2 to flag the others (WIA010), and run `wiaudit collect github` "
            "to detect personal accounts automatically.",
            target="tenant",
            details={"owners": counts},
        )


def run_identity_rules(
    snapshot: AzureSnapshot,
    inventory: dict[str, RepoInfo] | None = None,
    missing_repos: set[str] | None = None,
    renamed: dict[str, str] | None = None,
    allowed_owners: set[str] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for ident in snapshot.identities:
        findings.extend(check_identity(ident, inventory, missing_repos, renamed))
    findings.extend(check_owners(snapshot, inventory, allowed_owners))
    return findings
