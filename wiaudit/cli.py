"""Command line interface."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .azure_snapshot import load_missing_repos, load_repo_inventory, load_snapshot, save_json
from .collectors import CollectorError, collect_azure, collect_github, repos_referenced_by_snapshot
from .doctor import diagnose
from .github_workflows import detect_repo_slug, load_workflows
from .models import AzureSnapshot, RepoInfo, Severity
from .report import render
from .rules import RULES
from .rules.identity_rules import run_identity_rules
from .rules.workflow_rules import run_workflow_rules


def _inventory(path: str | None):
    if not path:
        return {}, set(), {}
    import json

    inv = load_repo_inventory(path)
    missing = load_missing_repos(path)
    renamed = {}
    for r in json.loads(Path(path).read_text(encoding="utf-8")):
        if r.get("renamedFrom"):
            renamed[r["renamedFrom"].lower()] = r["fullName"]
    return inv, missing, renamed


def _repo_info(repo_path: str, slug: str | None, inventory: dict[str, RepoInfo]) -> RepoInfo | None:
    slug = slug or detect_repo_slug(repo_path)
    if not slug:
        return None
    return inventory.get(slug.lower()) or RepoInfo(full_name=slug)


def cmd_scan(args: argparse.Namespace) -> int:
    findings = []
    errors: list[str] = []
    snapshot: AzureSnapshot | None = load_snapshot(args.azure) if args.azure else None
    inventory, missing, renamed = _inventory(args.github)
    all_workflows = []

    if snapshot:
        allowed = {o.strip() for o in args.allowed_owners.split(',') if o.strip()} if args.allowed_owners else None
        findings += run_identity_rules(snapshot, inventory, missing, renamed, allowed)

    for repo_path in args.repo or []:
        workflows, errs = load_workflows(repo_path)
        errors += errs
        all_workflows += workflows
        findings += run_workflow_rules(workflows)
        if snapshot and workflows:
            repo = _repo_info(repo_path, args.repo_slug if len(args.repo) == 1 else None, inventory)
            if repo:
                _diag, doc_findings = diagnose(workflows, snapshot, repo)
                findings += doc_findings
            else:
                errors.append(f"{repo_path}: could not detect owner/repo; pass --repo-slug to enable the doctor checks")

    threshold = Severity.parse(args.min_severity)
    findings = [f for f in findings if f.severity >= threshold]
    meta = {
        "version": __version__,
        "tenantId": snapshot.tenant_id if snapshot else None,
        "identities": len(snapshot.identities) if snapshot else 0,
        "workflows": len(all_workflows),
        "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "firstWorkflow": all_workflows[0].path if all_workflows else None,
        "errors": errors,
    }
    out = render(args.format, findings, meta)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"report written to {args.output}", file=sys.stderr)
    else:
        print(out)
    if args.fail_on and any(f.severity >= Severity.parse(args.fail_on) for f in findings):
        return 2
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    snapshot = load_snapshot(args.azure)
    inventory, _missing, _renamed = _inventory(args.github)
    workflows, errs = load_workflows(args.repo)
    repo = _repo_info(args.repo, args.repo_slug, inventory)
    if not repo:
        print("Could not detect owner/repo from git remote. Pass --repo-slug owner/repo.", file=sys.stderr)
        return 1
    diags, _ = diagnose(workflows, snapshot, repo)
    if not diags:
        print("No jobs using azure/login with OIDC were found.")
    icon = {
        "ok": "OK  ",
        "ok-unverified": "OK? ",
        "partial": "PART",
        "no-match": "FAIL",
        "no-permission": "FAIL",
        "unknown-identity": "????",
    }
    bad = 0
    for d in diags:
        print(f"[{icon[d.status]}] {d.workflow} -> job '{d.job}'")
        ids = (d.identity or "-").split(", ")
        shown = ", ".join(ids[:2]) + (f" (+{len(ids) - 2} more)" if len(ids) > 2 else "")
        print(f"       identity: {shown}")
        for s in d.matched:
            print(f"       accepted: {s}")
        for s in d.unmatched:
            print(f"       REJECTED: {s}")
        for c in d.closest:
            print(f"       closest credential subject: {c}")
        for h in d.hints:
            print(f"       hint: {h}")
        print()
        bad += d.status not in ("ok", "ok-unverified")
    for e in errs:
        print(f"warning: {e}", file=sys.stderr)
    return 2 if bad else 0


def cmd_collect_azure(args: argparse.Namespace) -> int:
    try:
        data = collect_azure(
            subscriptions=args.subscription,
            all_subscriptions=args.all_subscriptions,
            app_name_prefix=args.app_prefix,
            include_apps=not args.no_apps,
            all_issuers=args.all_issuers,
            include_managed_identities=not args.no_managed_identities,
        )
    except CollectorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    save_json(data, args.output)
    print(f"{len(data['identities'])} identities with federated credentials written to {args.output}", file=sys.stderr)
    if data.get("warnings"):
        print(f"{len(data['warnings'])} warning(s): some data is missing (see 'warnings' in the file); rerun later to complete it", file=sys.stderr)
    return 0


def cmd_collect_github(args: argparse.Namespace) -> int:
    import json

    repos = list(args.repo or [])
    if args.from_azure:
        repos += repos_referenced_by_snapshot(json.loads(Path(args.from_azure).read_text(encoding="utf-8")))
    repos = sorted(set(repos))
    if not repos:
        print("Nothing to collect: pass --repo owner/repo or --from-azure snapshot.json", file=sys.stderr)
        return 1
    try:
        data = collect_github(repos)
    except CollectorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    save_json(data, args.output)
    gone = sum(1 for r in data if r.get("exists") is False)
    print(f"{len(data)} repos written to {args.output} ({gone} not found)", file=sys.stderr)
    return 0


def cmd_rules(_args: argparse.Namespace) -> int:
    for rid, title in RULES.items():
        print(f"{rid}  {title}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wiaudit",
        description="Workload Identity Auditor - read-only audit of OIDC trust between GitHub Actions and Azure.",
    )
    p.add_argument("--version", action="version", version=f"wiaudit {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="run all rules and produce a report")
    s.add_argument("--azure", help="Azure snapshot JSON from `wiaudit collect azure`")
    s.add_argument("--repo", action="append", help="path to a local git repo (repeatable)")
    s.add_argument("--repo-slug", help="owner/repo when it cannot be read from the git remote")
    s.add_argument("--github", help="repos.json from `wiaudit collect github` (IDs, renames, deleted repos)")
    s.add_argument("--format", choices=["text", "json", "sarif", "html"], default="text")
    s.add_argument("--output", "-o", help="write the report to a file")
    s.add_argument("--min-severity", default="info", choices=[x.label for x in Severity])
    s.add_argument(
        "--allowed-owners",
        help="comma-separated GitHub orgs/users you trust; credentials for other owners are flagged (WIA010)",
    )
    s.add_argument("--fail-on", choices=[x.label for x in Severity], help="exit 2 if a finding at this level or above exists")
    s.set_defaults(func=cmd_scan)

    d = sub.add_parser("doctor", help="explain why a workflow does (not) get an Azure token")
    d.add_argument("--azure", required=True)
    d.add_argument("--repo", default=".")
    d.add_argument("--repo-slug")
    d.add_argument("--github")
    d.set_defaults(func=cmd_doctor)

    c = sub.add_parser("collect", help="read-only collection using your az / gh login")
    csub = c.add_subparsers(dest="source", required=True)
    ca = csub.add_parser("azure", help="apps and managed identities with federated credentials, plus role assignments")
    ca.add_argument("--subscription", action="append", help="subscription id (repeatable; default: current)")
    ca.add_argument("--all-subscriptions", action="store_true")
    ca.add_argument("--app-prefix", help="only app registrations whose name starts with this")
    ca.add_argument("--no-apps", action="store_true")
    ca.add_argument(
        "--all-issuers",
        action="store_true",
        help="inspect every app registration, not only those trusting GitHub (slow in large tenants; enables WIA009)",
    )
    ca.add_argument("--no-managed-identities", action="store_true")
    ca.add_argument("--output", "-o", default="azure-snapshot.json")
    ca.set_defaults(func=cmd_collect_azure)
    cg = csub.add_parser("github", help="repo IDs, renames and deleted repos via `gh api`")
    cg.add_argument("--repo", action="append", help="owner/repo (repeatable)")
    cg.add_argument("--from-azure", help="also collect every repo referenced by credentials in this snapshot")
    cg.add_argument("--output", "-o", default="repos.json")
    cg.set_defaults(func=cmd_collect_github)

    r = sub.add_parser("rules", help="list rules")
    r.set_defaults(func=cmd_rules)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        name = exc.filename or str(exc)
        msg = f"error: file or folder not found: {name}"
        if getattr(args, "azure", None) and str(name).endswith(str(args.azure)):
            msg += "\nhint: create it first with `wiaudit collect azure -o " + str(args.azure) + "`"
        print(msg, file=sys.stderr)
        return 1
    except CollectorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
