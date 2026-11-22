"""GitHub Actions OIDC subject claims: parsing, prediction and matching.

Subject formats handled (GitHub docs, "OpenID Connect reference"):
  name-based : repo:OWNER/REPO:<context>
  immutable  : repo:OWNER@OWNER-ID/REPO@REPO-ID:<context>
where <context> is environment:NAME | ref:refs/heads/B | ref:refs/tags/T | pull_request.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass

from .models import FederatedCredential, Job, RepoInfo, Workflow

_SUBJECT_RE = re.compile(
    r"^repo:(?P<owner>[^/@:]+)(?:@(?P<owner_id>\d+))?/(?P<repo>[^/@:]+)(?:@(?P<repo_id>\d+))?:(?P<context>.+)$"
)


@dataclass
class ParsedSubject:
    owner: str
    repo: str
    owner_id: str | None
    repo_id: str | None
    context: str

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def is_immutable(self) -> bool:
        return bool(self.owner_id and self.repo_id)

    @property
    def context_kind(self) -> str:
        if self.context.startswith("environment:"):
            return "environment"
        if self.context.startswith("ref:refs/tags/"):
            return "tag"
        if self.context.startswith("ref:"):
            return "branch"
        if self.context == "pull_request":
            return "pull_request"
        return "custom"


def parse_subject(subject: str | None) -> ParsedSubject | None:
    if not subject:
        return None
    m = _SUBJECT_RE.match(subject.strip())
    if not m:
        return None
    return ParsedSubject(
        owner=m.group("owner"),
        repo=m.group("repo"),
        owner_id=m.group("owner_id"),
        repo_id=m.group("repo_id"),
        context=m.group("context"),
    )


def repo_prefix(repo: RepoInfo, immutable: bool) -> str:
    if immutable:
        if not (repo.owner_id and repo.repo_id):
            raise ValueError("immutable prefix needs owner_id and repo_id")
        return f"repo:{repo.owner}@{repo.owner_id}/{repo.name}@{repo.repo_id}"
    return f"repo:{repo.full_name}"


# ------------------------------------------------------- expected subjects


@dataclass
class ExpectedSubject:
    context: str  # e.g. "environment:prod", "ref:refs/heads/main", "pull_request"
    trigger: str  # event that produces it
    is_pattern: bool = False  # True when the branch/tag is not known exactly
    note: str | None = None

    def full(self, prefix: str) -> str:
        return f"{prefix}:{self.context}"


_ANY_BRANCH = "ref:refs/heads/*"


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def expected_contexts(workflow: Workflow, job: Job) -> list[ExpectedSubject]:
    """Predict which subject contexts GitHub will send for this job.

    GitHub rule: if the job references an environment, the subject is
    environment-based regardless of the event.
    """
    if job.environment:
        return [ExpectedSubject(f"environment:{job.environment}", trigger="(environment)")]

    out: list[ExpectedSubject] = []
    for event, cfg in workflow.triggers.items():
        cfg = cfg if isinstance(cfg, dict) else {}
        if event == "push":
            branches = _as_list(cfg.get("branches"))
            tags = _as_list(cfg.get("tags"))
            if not branches and not tags:
                out.append(ExpectedSubject(_ANY_BRANCH, "push", is_pattern=True, note="any pushed branch"))
            for b in branches:
                out.append(
                    ExpectedSubject(f"ref:refs/heads/{b}", "push", is_pattern=any(c in b for c in "*?["))
                )
            for t in tags:
                out.append(
                    ExpectedSubject(f"ref:refs/tags/{t}", "push", is_pattern=any(c in t for c in "*?["))
                )
        elif event == "pull_request":
            out.append(ExpectedSubject("pull_request", "pull_request"))
        elif event == "pull_request_target":
            out.append(
                ExpectedSubject(
                    "pull_request",
                    "pull_request_target",
                    note="verify the sub in a real token: pull_request_target runs in the base branch context",
                )
            )
        else:
            # workflow_dispatch, schedule, workflow_call, release, ... run on a ref
            out.append(
                ExpectedSubject(_ANY_BRANCH, event, is_pattern=True, note="branch chosen at run time (often the default branch)")
            )
    # de-duplicate, keep order
    seen: set[str] = set()
    uniq = []
    for e in out:
        if e.context not in seen:
            seen.add(e.context)
            uniq.append(e)
    return uniq


def expected_full_subjects(
    workflow: Workflow, job: Job, repo: RepoInfo
) -> list[tuple[ExpectedSubject, str, str]]:
    """Return (expected, full_subject, format) for each plausible format.

    format is "name-based" or "immutable". When we cannot tell which format the
    repo uses, both are returned.
    """
    expects = repo.expects_immutable()
    formats: list[str]
    if expects is True and repo.owner_id and repo.repo_id:
        formats = ["immutable"]
    elif expects is False or not (repo.owner_id and repo.repo_id):
        formats = ["name-based"]
    else:
        formats = ["name-based", "immutable"]
    result = []
    for exp in expected_contexts(workflow, job):
        for fmt in formats:
            result.append((exp, exp.full(repo_prefix(repo, fmt == "immutable")), fmt))
    return result


# ----------------------------------------------------------------- matching

_EXPR_SUB_RE = re.compile(
    r"claims\[\s*'sub'\s*\]\s+(?P<op>eq|matches)\s+'(?P<val>[^']*)'", re.IGNORECASE
)
_EXPR_IMMUTABLE_RE = re.compile(r"claims\[\s*'(repository_id|repository_owner_id)'\s*\]", re.IGNORECASE)


def flexible_sub_patterns(expr: str) -> list[tuple[str, str]]:
    """Extract (operator, value) pairs for the sub claim from a flexible FIC expression."""
    return [(m.group("op").lower(), m.group("val")) for m in _EXPR_SUB_RE.finditer(expr or "")]


def flexible_binds_immutable_claim(expr: str) -> bool:
    return bool(_EXPR_IMMUTABLE_RE.search(expr or ""))


def credential_matches(fic: FederatedCredential, subject: str) -> bool:
    """Does this credential accept a token with this subject? (subject only)

    For flexible credentials only the sub part of the expression is evaluated;
    other claim checks (repository_id etc.) are reported separately.
    """
    if fic.subject is not None and not fic.is_flexible:
        return fic.subject == subject  # Entra compares the subject exactly
    for op, val in flexible_sub_patterns(fic.claims_matching_expression or ""):
        if op == "eq" and val == subject:
            return True
        if op == "matches" and fnmatch.fnmatchcase(subject, val):
            return True
    return False


def pattern_overlaps(pattern_subject: str, fic: FederatedCredential) -> bool:
    """For a predicted subject with wildcards (unknown branch), does the credential
    accept at least one concrete value of it?"""
    if fic.subject and not fic.is_flexible:
        return fnmatch.fnmatchcase(fic.subject, pattern_subject)
    for _op, val in flexible_sub_patterns(fic.claims_matching_expression or ""):
        if fnmatch.fnmatchcase(val, pattern_subject) or fnmatch.fnmatchcase(pattern_subject, val):
            return True
    return False
