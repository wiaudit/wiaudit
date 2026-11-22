"""Rules that look only at GitHub Actions workflow files."""

from __future__ import annotations

from typing import Iterable

from ..github_workflows import effective_id_token, id_token_permission
from ..models import Finding, Severity, Workflow


def check_workflow(wf: Workflow) -> Iterable[Finding]:
    uses_oidc_login = any(ls.uses_oidc for job in wf.jobs for ls in job.login_steps)
    jobs_with_id_token = []
    for job in wf.jobs:
        perm, _src = effective_id_token(wf, job)
        if perm == "write":
            jobs_with_id_token.append(job)

    # WIA101: pull_request_target + id-token
    if "pull_request_target" in wf.triggers and jobs_with_id_token:
        yield Finding(
            rule_id="WIA101",
            severity=Severity.CRITICAL,
            title="pull_request_target workflow can request OIDC tokens",
            message=f"{wf.path} runs on pull_request_target and jobs "
            f"{', '.join(j.job_id for j in jobs_with_id_token)} have id-token: write. "
            "pull_request_target runs with repository secrets and permissions, so a crafted PR "
            "that gets code executed here can obtain cloud tokens.",
            remediation="Do not grant id-token: write in pull_request_target workflows. Split into a "
            "pull_request workflow (no cloud access) and a deployment workflow on push / environment.",
            target=wf.path,
            location=wf.path,
            line=jobs_with_id_token[0].line,
        )

    # WIA102: id-token at workflow level for all jobs
    if id_token_permission(wf.permissions) == "write" and len(wf.jobs) > 1:
        inheriting = [j.job_id for j in wf.jobs if j.permissions is None]
        if len(inheriting) > 1:
            yield Finding(
                rule_id="WIA102",
                severity=Severity.LOW,
                title="id-token: write granted to every job in the workflow",
                message=f"{wf.path} sets id-token: write at workflow level; jobs {', '.join(inheriting)} inherit it "
                "even if they never log in to the cloud.",
                remediation="Move `permissions: id-token: write` to the job that runs azure/login.",
                target=wf.path,
                location=wf.path,
            )

    for job in wf.jobs:
        for ls in job.login_steps:
            # WIA103: secret-based login
            if ls.uses_secret_creds:
                yield Finding(
                    rule_id="WIA103",
                    severity=Severity.MEDIUM,
                    title="azure/login uses a client secret instead of OIDC",
                    message=f"Job '{job.job_id}' in {wf.path} logs in with `creds:` (a long-lived client secret).",
                    remediation="Switch to OIDC: add a federated credential to the identity, use client-id / tenant-id / "
                    "subscription-id inputs, grant id-token: write, then delete the secret.",
                    target=wf.path,
                    location=wf.path,
                    line=ls.line,
                )
            # WIA104: OIDC login without id-token permission
            if ls.uses_oidc:
                perm, src = effective_id_token(wf, job)
                if perm != "write":
                    why = {
                        "default": "no permissions block exists, and default token permissions never include id-token",
                        "workflow": f"workflow-level permissions give id-token: {perm or 'not set'}",
                        "job": f"job-level permissions give id-token: {perm or 'not set'} (job permissions replace workflow ones)",
                    }[src]
                    yield Finding(
                        rule_id="WIA104",
                        severity=Severity.MEDIUM,
                        title="azure/login OIDC step without id-token: write",
                        message=f"Job '{job.job_id}' in {wf.path} uses azure/login with OIDC but cannot request a token: {why}.",
                        remediation="Add to the job:\n  permissions:\n    id-token: write\n    contents: read",
                        target=wf.path,
                        location=wf.path,
                        line=ls.line,
                    )
    _ = uses_oidc_login  # reserved for future rules


def run_workflow_rules(workflows: list[Workflow]) -> list[Finding]:
    out: list[Finding] = []
    for wf in workflows:
        out.extend(check_workflow(wf))
    return out
