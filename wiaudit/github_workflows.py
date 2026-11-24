"""Parse GitHub Actions workflow files into the small model the rules need."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

import yaml

from .models import Job, LoginStep, Workflow

_LINE = "__line__"


class _LineLoader(yaml.SafeLoader):
    """SafeLoader that remembers the source line of every mapping."""


def _construct_mapping(loader: _LineLoader, node: yaml.MappingNode, deep: bool = False):
    mapping = yaml.SafeLoader.construct_mapping(loader, node, deep=deep)
    mapping[_LINE] = node.start_mark.line + 1
    return mapping


_LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def _clean(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items() if k != _LINE}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


def _normalize_triggers(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {}
    if isinstance(raw, str):
        return {raw: {}}
    if isinstance(raw, list):
        return {str(e): {} for e in raw}
    if isinstance(raw, dict):
        return {str(k): (_clean(v) if v is not None else {}) for k, v in raw.items() if k != _LINE}
    return {}


def _normalize_permissions(raw: Any) -> dict[str, str] | str | None:
    if raw is None:
        return None
    if isinstance(raw, str):
        return raw.strip()
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items() if k != _LINE}
    return None


def id_token_permission(perms: dict[str, str] | str | None) -> str | None:
    """Return 'write', 'read', 'none' or None (not granted / key absent)."""
    if perms is None:
        return None
    if isinstance(perms, str):
        if perms == "write-all":
            return "write"
        if perms == "read-all":
            return "read"
        return None
    return perms.get("id-token")


def effective_id_token(workflow: Workflow, job: Job) -> tuple[str | None, str]:
    """Effective id-token permission for a job and where it comes from.

    Job-level permissions replace workflow-level ones entirely. With no
    permissions key anywhere GitHub uses default token permissions, which never
    include id-token.
    """
    if job.permissions is not None:
        return id_token_permission(job.permissions), "job"
    if workflow.permissions is not None:
        return id_token_permission(workflow.permissions), "workflow"
    return None, "default"


def _parse_login_step(step: dict[str, Any]) -> LoginStep | None:
    uses = str(step.get("uses", ""))
    if not uses.lower().startswith("azure/login@"):
        return None
    with_ = step.get("with") or {}
    client_id = with_.get("client-id")
    creds = with_.get("creds")
    return LoginStep(
        uses=uses,
        client_id=str(client_id) if client_id is not None else None,
        uses_oidc=client_id is not None and creds is None,
        uses_secret_creds=creds is not None,
        line=step.get(_LINE),
    )


def parse_workflow_text(text: str, rel_path: str) -> Workflow:
    data = yaml.load(text, Loader=_LineLoader) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{rel_path}: not a workflow mapping")
    # YAML 1.1 turns the bare key `on` into boolean True
    raw_on = data.get("on", data.get(True))
    wf = Workflow(
        path=rel_path,
        name=data.get("name"),
        triggers=_normalize_triggers(raw_on),
        permissions=_normalize_permissions(data.get("permissions")),
    )
    for job_id, job_raw in (data.get("jobs") or {}).items():
        if job_id == _LINE or not isinstance(job_raw, dict):
            continue
        env = job_raw.get("environment")
        if isinstance(env, dict):
            env = env.get("name")
        job = Job(
            job_id=str(job_id),
            environment=str(env) if env is not None else None,
            permissions=_normalize_permissions(job_raw.get("permissions")),
            line=job_raw.get(_LINE),
        )
        for step in job_raw.get("steps") or []:
            if isinstance(step, dict):
                ls = _parse_login_step(step)
                if ls:
                    job.login_steps.append(ls)
        wf.jobs.append(job)
    return wf


def load_workflows(repo_root: str | Path) -> tuple[list[Workflow], list[str]]:
    """Load all workflows under .github/workflows. Returns (workflows, errors)."""
    root = Path(repo_root)
    wf_dir = root / ".github" / "workflows"
    workflows, errors = [], []
    if not root.is_dir():
        raise FileNotFoundError(2, "repository folder not found", str(root))
    if not wf_dir.is_dir():
        errors.append(f"{root}: no .github/workflows folder, nothing to check in this repo")
        return workflows, errors
    for path in sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml"))):
        rel = path.relative_to(root).as_posix()
        try:
            workflows.append(parse_workflow_text(path.read_text(encoding="utf-8"), rel))
        except Exception as exc:  # broken YAML should not stop the audit
            errors.append(f"{rel}: {exc}")
    return workflows, errors


_REMOTE_RE = re.compile(r"github\.com[:/](?P<full>[^/\s]+/[^/\s]+?)(?:\.git)?/?$")


def detect_repo_slug(repo_root: str | Path) -> str | None:
    """Best effort owner/repo from `git remote get-url origin`."""
    try:
        url = subprocess.run(
            ["git", "-C", str(repo_root), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout.strip()
    except Exception:
        return None
    m = _REMOTE_RE.search(url)
    return m.group("full") if m else None


def is_expression(value: str | None) -> bool:
    return bool(value) and "${{" in value
