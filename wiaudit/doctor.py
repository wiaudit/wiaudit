"""Doctor: explain whether each azure/login job will get a token, and if not, why.

Typical Entra error when nothing matches: AADSTS700213
("No matching federated identity record found for presented assertion subject").
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field

from .github_workflows import effective_id_token, is_expression
from .models import AzureSnapshot, FederatedCredential, Finding, Identity, Job, RepoInfo, Severity, Workflow
from .subjects import (
    credential_matches,
    expected_full_subjects,
    flexible_sub_patterns,
    parse_subject,
    pattern_overlaps,
)

_GUID = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")


@dataclass
class JobDiagnosis:
    workflow: str
    job: str
    status: str  # "ok" | "no-match" | "no-permission" | "unknown-identity" | "partial"
    identity: str | None
    expected: list[str] = field(default_factory=list)
    matched: list[str] = field(default_factory=list)
    unmatched: list[str] = field(default_factory=list)
    closest: list[str] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)
    line: int | None = None


def _fic_subjects(fic: FederatedCredential) -> list[str]:
    if fic.subject and not fic.is_flexible:
        return [fic.subject]
    return [v for _op, v in flexible_sub_patterns(fic.claims_matching_expression or "")]


def _candidate_identities(snapshot: AzureSnapshot, client_id: str | None, repo: RepoInfo) -> tuple[list[Identity], str]:
    if client_id and _GUID.match(client_id):
        ids = [i for i in snapshot.identities if i.client_id.lower() == client_id.lower()]
        return ids, ("client-id " + client_id if ids else f"client-id {client_id} not found in snapshot")
    # client-id is a secret/variable expression: use identities that trust this repo
    repo_l = repo.full_name.lower()
    ids = []
    for ident in snapshot.identities:
        for fic in ident.federated_credentials:
            for s in _fic_subjects(fic):
                p = parse_subject(s)
                if p and p.full_name.lower() == repo_l:
                    ids.append(ident)
                    break
            else:
                continue
            break
    how = f"client-id is {client_id!r} (resolved at run time); checked identities that trust {repo.full_name}"
    return ids, how


def _hints(job: Job, repo: RepoInfo, expected_subjects: list[str], fics: list[FederatedCredential]) -> list[str]:
    hints: list[str] = []
    fic_subjects = [s for f in fics for s in _fic_subjects(f)]
    parsed = [p for p in (parse_subject(s) for s in fic_subjects) if p]
    repo_l = repo.full_name.lower()
    same_repo = [p for p in parsed if p.full_name.lower() == repo_l]

    if not same_repo:
        others = sorted({p.full_name for p in parsed})
        hints.append(
            f"No credential trusts {repo.full_name} at all"
            + (f" (credentials trust: {', '.join(others[:5])})." if others else ".")
            + " If the repo was renamed or transferred, the subject changed."
        )
    if job.environment and same_repo and not any(p.context_kind == "environment" for p in same_repo):
        hints.append(
            f"The job uses environment '{job.environment}', so GitHub sends an environment subject "
            "(repo:...:environment:NAME), not a branch subject. Add a credential for the environment."
        )
    if not job.environment and same_repo and all(p.context_kind == "environment" for p in same_repo):
        hints.append(
            "Credentials only trust environment subjects, but this job has no `environment:`. "
            "Add the environment to the job or a credential for the branch."
        )
    if any(p.is_immutable for p in same_repo) and not any("@" in e for e in expected_subjects):
        hints.append(
            "Credentials use the immutable format (owner@id/repo@id) but this repo's IDs are unknown here. "
            "Run `wiaudit collect github` so the doctor can compute the immutable subject."
        )
    if same_repo and not any(p.is_immutable for p in same_repo):
        exp = repo.expects_immutable()
        if exp is True:
            hints.append(
                "This repo was created, renamed or transferred on/after 2026-07-15, so GitHub sends the immutable "
                "subject (repo:OWNER@OWNER_ID/REPO@REPO_ID:...). The name-based credentials will not match."
            )
        elif exp is None:
            hints.append(
                "If this repo was created, renamed or transferred on/after 2026-07-15 (or opted in), GitHub sends the "
                "immutable subject format and name-based credentials will not match."
            )
    lowered = {s.lower(): s for s in fic_subjects}
    for e in expected_subjects:
        if e not in fic_subjects and e.lower() in lowered:
            hints.append(f"Case differs: credential has '{lowered[e.lower()]}', token will have '{e}'. Matching is exact.")
    return hints


def repo_ids_from_snapshot(snapshot: AzureSnapshot, repo: RepoInfo) -> tuple[RepoInfo, bool]:
    """If the repo's IDs are unknown but a credential already uses the immutable subject for it
    (repo:OWNER@OWNER_ID/REPO@REPO_ID:...), take the IDs from there. Returns (repo, inferred)."""
    if repo.owner_id and repo.repo_id:
        return repo, False
    repo_l = repo.full_name.lower()
    for ident in snapshot.identities:
        for fic in ident.federated_credentials:
            if not fic.is_github:
                continue
            for s in _fic_subjects(fic):
                p = parse_subject(s)
                if p and p.is_immutable and p.full_name.lower() == repo_l and p.owner_id and p.repo_id:
                    if any(c in (p.owner_id + p.repo_id) for c in "*?"):
                        continue
                    return (
                        RepoInfo(
                            full_name=p.full_name,  # canonical casing as written in the credential
                            owner_id=p.owner_id,
                            repo_id=p.repo_id,
                            created_at=repo.created_at,
                            uses_immutable=repo.uses_immutable,
                            owner_type=repo.owner_type,
                        ),
                        True,
                    )
    return repo, False


def diagnose(
    workflows: list[Workflow], snapshot: AzureSnapshot, repo: RepoInfo
) -> tuple[list[JobDiagnosis], list[Finding]]:
    diagnoses: list[JobDiagnosis] = []
    findings: list[Finding] = []
    repo, ids_inferred = repo_ids_from_snapshot(snapshot, repo)
    seen: set[tuple[str, str, str | None]] = set()
    for wf in workflows:
        for job in wf.jobs:
            for ls in job.login_steps:
                if not ls.uses_oidc:
                    continue
                key = (wf.path, job.job_id, ls.client_id)
                if key in seen:  # several azure/login steps with the same identity: one diagnosis
                    continue
                seen.add(key)
                perm, _src = effective_id_token(wf, job)
                idents, how = _candidate_identities(snapshot, ls.client_id, repo)
                exp = expected_full_subjects(wf, job, repo)
                d = JobDiagnosis(
                    workflow=wf.path,
                    job=job.job_id,
                    status="ok",
                    identity=", ".join(i.ref for i in idents) or None,
                    expected=[s for _e, s, _f in exp],
                    line=ls.line,
                )
                if perm != "write":
                    d.status = "no-permission"
                    d.hints.append("The job lacks id-token: write, so GitHub never issues a token (see WIA104).")
                if not idents:
                    d.status = "unknown-identity" if d.status == "ok" else d.status
                    d.hints.append(
                        f"No identity found in the Azure snapshot ({how}). "
                        "Check that the snapshot covers the right tenant / subscriptions and that the app or managed "
                        "identity has federated credentials."
                    )
                    diagnoses.append(d)
                    continue

                fics = [f for i in idents for f in i.federated_credentials if f.is_github]
                # group by expected context; a context is satisfied if any format matches
                by_context: dict[str, list[str]] = {}
                ok_contexts: set[str] = set()
                for e, full, _fmt in exp:
                    by_context.setdefault(e.context, []).append(full)
                    hit = any(
                        (pattern_overlaps(full, f) if e.is_pattern else credential_matches(f, full)) for f in fics
                    )
                    if hit:
                        ok_contexts.add(e.context)
                        d.matched.append(full)
                for ctx, fulls in by_context.items():
                    if ctx not in ok_contexts:
                        d.unmatched.extend(fulls)

                if d.unmatched:
                    all_fic_subjects = [s for f in fics for s in _fic_subjects(f)]
                    for u in d.unmatched:
                        for c in difflib.get_close_matches(u, all_fic_subjects, n=2, cutoff=0.6):
                            if c not in d.closest:
                                d.closest.append(c)
                    d.hints.extend(_hints(job, repo, d.unmatched, fics))
                    if d.status == "ok":
                        d.status = "partial" if d.matched else "no-match"

                if ids_inferred and any("@" in m for m in d.matched):
                    d.hints.append(
                        "Repo IDs were taken from an existing immutable credential (no `wiaudit collect github` needed)."
                    )

                if (
                    d.status == "ok"
                    and repo.expects_immutable() is None
                    and d.matched
                    and all("@" not in s for s in d.matched)
                ):
                    d.status = "ok-unverified"
                    d.hints.append(
                        "Matched with the name-based subject, but the repo's creation date / IDs are unknown. If it was "
                        "created, renamed or transferred on/after 2026-07-15 (or opted in), GitHub sends the immutable "
                        "subject instead. Run `wiaudit collect github` to confirm."
                    )

                if d.status in ("no-match", "partial"):
                    findings.append(
                        Finding(
                            rule_id="WIA201",
                            severity=Severity.MEDIUM if d.status == "no-match" else Severity.LOW,
                            title="No federated credential matches the subject this job will send",
                            message=f"Job '{job.job_id}' in {wf.path}: no credential on {d.identity} accepts "
                            f"{', '.join(d.unmatched)}. Entra will reject the token (typically AADSTS700213).",
                            remediation=" ".join(d.hints) or "Add a federated credential with the exact subject above.",
                            target=wf.path,
                            location=wf.path,
                            line=ls.line,
                            details={"expected": d.unmatched, "closest": d.closest},
                        )
                    )
                diagnoses.append(d)
    return diagnoses, findings


def is_client_id_expression(value: str | None) -> bool:
    return is_expression(value)
