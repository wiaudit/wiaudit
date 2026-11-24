"""Local MCP server (stdio) so AI agents (Claude Code, Copilot, Cursor...) can call wiaudit.

Read-only: tools only read local files (an Azure snapshot JSON, a repo checkout,
an optional repos.json). The server never calls Azure or GitHub and never sees
credentials. Run `wiaudit collect ...` yourself to produce the input files.

    pip install "wiaudit[mcp]"
    wiaudit-mcp            # speaks MCP over stdio
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from .azure_snapshot import load_snapshot
from .doctor import diagnose
from .github_workflows import load_workflows
from .models import Severity
from .report import sort_findings, summary
from .rules import RULES
from .rules.identity_rules import run_identity_rules
from .rules.workflow_rules import run_workflow_rules

INSTRUCTIONS = (
    "wiaudit audits GitHub Actions -> Microsoft Entra / Azure OIDC trust (federated identity credentials). "
    "All tools are read-only and work on local files. To get an Azure snapshot, ask the user to run "
    "`wiaudit collect azure -o azure-snapshot.json` (and optionally `wiaudit collect github --from-azure "
    "azure-snapshot.json -o repos.json`). Use `doctor` to explain AADSTS700213 / 'no matching federated "
    "identity record' errors for a repo, and `scan` for a risk report."
)


def _inventory(path: str | None):
    from .cli import _inventory as inv

    return inv(path)


def tool_scan(
    azure_snapshot: str | None = None,
    repo_path: str | None = None,
    repo_slug: str | None = None,
    github_inventory: str | None = None,
    min_severity: str = "low",
    allowed_owners: list[str] | None = None,
) -> dict[str, Any]:
    """Audit federated identity credentials and/or GitHub workflows. Returns findings with fixes."""
    findings = []
    errors: list[str] = []
    snapshot = load_snapshot(azure_snapshot) if azure_snapshot else None
    inventory, missing, renamed = _inventory(github_inventory)
    if snapshot:
        findings += run_identity_rules(snapshot, inventory, missing, renamed, set(allowed_owners) if allowed_owners else None)
    if repo_path:
        from .cli import _repo_info

        workflows, errs = load_workflows(repo_path)
        errors += errs
        findings += run_workflow_rules(workflows)
        if snapshot and workflows:
            repo = _repo_info(repo_path, repo_slug, inventory)
            if repo:
                findings += diagnose(workflows, snapshot, repo)[1]
    threshold = Severity.parse(min_severity)
    findings = sort_findings([f for f in findings if f.severity >= threshold])
    return {"summary": summary(findings), "findings": [f.to_dict() for f in findings], "errors": errors}


def tool_doctor(
    azure_snapshot: str,
    repo_path: str = ".",
    repo_slug: str | None = None,
    github_inventory: str | None = None,
) -> dict[str, Any]:
    """For each workflow job that logs in to Azure with OIDC, show the subject GitHub will send,
    whether a federated credential accepts it, the closest credential and why it fails."""
    from .cli import _repo_info

    snapshot = load_snapshot(azure_snapshot)
    inventory, _m, _r = _inventory(github_inventory)
    workflows, errs = load_workflows(repo_path)
    repo = _repo_info(repo_path, repo_slug, inventory)
    if not repo:
        return {"error": "Could not detect owner/repo from git remote; pass repo_slug='owner/repo'."}
    diags, _ = diagnose(workflows, snapshot, repo)
    return {"jobs": [asdict(d) for d in diags], "warnings": errs}


def tool_rules() -> list[dict[str, str]]:
    """List all wiaudit rules (id and title)."""
    return [{"id": rid, "title": title} for rid, title in RULES.items()]


def build_server():
    try:  # MCP Python SDK 2.x
        from mcp.server.mcpserver import MCPServer as Server
    except ImportError:  # 1.x
        from mcp.server.fastmcp import FastMCP as Server  # type: ignore

    server = Server(name="wiaudit", instructions=INSTRUCTIONS)
    try:
        from mcp.types import ToolAnnotations

        ro = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
    except Exception:  # pragma: no cover
        ro = None
    server.tool(name="scan", annotations=ro)(tool_scan)
    server.tool(name="doctor", annotations=ro)(tool_doctor)
    server.tool(name="list_rules", annotations=ro)(tool_rules)
    return server


def main() -> None:
    try:
        server = build_server()
    except ImportError:
        raise SystemExit('The MCP server needs the extra: pip install "wiaudit[mcp]"')
    server.run()


if __name__ == "__main__":
    main()
