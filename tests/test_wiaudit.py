import json
from pathlib import Path

import pytest

from wiaudit.azure_snapshot import load_repo_inventory, load_snapshot
from wiaudit.cli import main
from wiaudit.collectors import collect_azure, collect_github, repos_referenced_by_snapshot, CollectorError
from wiaudit.doctor import diagnose
from wiaudit.github_workflows import effective_id_token, load_workflows, parse_workflow_text
from wiaudit.models import FederatedCredential, RepoInfo, RoleAssignment, Severity
from wiaudit.report import render
from wiaudit.rules.identity_rules import run_identity_rules
from wiaudit.rules.workflow_rules import run_workflow_rules
from wiaudit.subjects import credential_matches, expected_contexts, parse_subject

FX = Path(__file__).parent / "fixtures"


@pytest.fixture
def snapshot():
    return load_snapshot(FX / "azure-snapshot.json")


@pytest.fixture
def inventory():
    return load_repo_inventory(FX / "repos.json")


# ----------------------------------------------------------------- subjects


def test_parse_name_based_and_immutable():
    a = parse_subject("repo:contoso/api:environment:prod")
    assert a.full_name == "contoso/api" and not a.is_immutable and a.context_kind == "environment"
    b = parse_subject("repo:contoso@5544123/api@821093847:ref:refs/heads/main")
    assert b.is_immutable and b.owner_id == "5544123" and b.context_kind == "branch"
    assert parse_subject("pipeline-42") is None


def test_environment_overrides_event():
    wf = parse_workflow_text(
        "on: [push, pull_request]\njobs:\n  d:\n    environment: prod\n    steps: []\n", "w.yml"
    )
    ctx = expected_contexts(wf, wf.jobs[0])
    assert [c.context for c in ctx] == ["environment:prod"]


def test_on_key_parsed_despite_yaml11_boolean():
    wf = parse_workflow_text("on:\n  push:\n    branches: [main]\njobs: {}\n", "w.yml")
    assert "push" in wf.triggers


def test_flexible_wildcard_matching():
    fic = FederatedCredential(
        name="x",
        issuer="https://token.actions.githubusercontent.com",
        subject=None,
        claims_matching_expression="claims['sub'] matches 'repo:contoso/*:ref:refs/heads/*' and claims['repository_id'] eq '1'",
    )
    assert credential_matches(fic, "repo:contoso/api:ref:refs/heads/main")
    assert not credential_matches(fic, "repo:evil/api:ref:refs/heads/main")


def test_role_scope_levels():
    assert RoleAssignment("Owner", "/subscriptions/x").scope_level == "subscription"
    assert RoleAssignment("Owner", "/subscriptions/x/resourceGroups/rg").scope_level == "resourceGroup"
    assert (
        RoleAssignment("Owner", "/providers/Microsoft.Management/managementGroups/mg").scope_level
        == "managementGroup"
    )


# -------------------------------------------------------------------- rules


def _ids(findings):
    return sorted({f.rule_id for f in findings})


def test_identity_rules(snapshot, inventory):
    findings = run_identity_rules(
        snapshot, inventory, missing_repos={"contoso/legacy-tool"}, renamed={"contoso/old-api": "contoso/payments-api"}
    )
    assert _ids(findings) == ["WIA001", "WIA002", "WIA003", "WIA004", "WIA005", "WIA006", "WIA007", "WIA009"]
    pr = next(f for f in findings if f.rule_id == "WIA003")
    assert pr.severity == Severity.CRITICAL  # pull_request trust + Owner on subscription
    # no duplicate WIA001 for flexible / dangling / renamed credentials
    wia001_targets = [f.target for f in findings if f.rule_id == "WIA001"]
    assert not any("any-branch" in t or "legacy-tool" in t or "old-name" in t for t in wia001_targets)
    # suggestion uses real IDs from inventory
    prod = next(f for f in findings if f.rule_id == "WIA001" and "'prod'" in f.target)
    assert "repo:contoso@5544123/payments-api@821093847:environment:prod" in prod.remediation


def test_workflow_rules():
    wfs, errs = load_workflows(FX / "repo_main")
    assert not errs and len(wfs) == 4
    assert _ids(run_workflow_rules(wfs)) == ["WIA101", "WIA102", "WIA103", "WIA104"]


def test_effective_id_token_job_replaces_workflow():
    wf = parse_workflow_text(
        "on: push\npermissions:\n  id-token: write\njobs:\n  a:\n    permissions:\n      contents: read\n    steps: []\n",
        "w.yml",
    )
    assert effective_id_token(wf, wf.jobs[0]) == (None, "job")


# ------------------------------------------------------------------- doctor


def test_doctor_detects_immutable_mismatch(snapshot, inventory):
    wfs, _ = load_workflows(FX / "repo_new")
    diags, findings = diagnose(wfs, snapshot, inventory["contoso/new-svc"])
    assert diags[0].status == "no-match"
    assert diags[0].unmatched == ["repo:contoso@5544123/new-svc@900001:ref:refs/heads/main"]
    assert "repo:contoso/new-svc:ref:refs/heads/main" in diags[0].closest
    assert any("2026-07-15" in h for h in diags[0].hints)
    assert findings and findings[0].rule_id == "WIA201"


def test_doctor_unverified_without_ids(snapshot):
    wfs, _ = load_workflows(FX / "repo_new")
    diags, findings = diagnose(wfs, snapshot, RepoInfo("contoso/new-svc"))
    assert diags[0].status == "ok-unverified" and not findings


def test_doctor_environment_ok_and_missing_permission(snapshot, inventory):
    wfs, _ = load_workflows(FX / "repo_main")
    diags, _ = diagnose(wfs, snapshot, inventory["contoso/payments-api"])
    by_job = {d.job: d for d in diags}
    assert by_job["deploy"].status == "ok"
    assert by_job["plan"].status == "no-permission"


def test_doctor_environment_hint():
    from wiaudit.models import AzureSnapshot, Identity

    snap = AzureSnapshot(
        tenant_id="t",
        identities=[
            Identity(
                kind="app",
                display_name="a",
                client_id="11111111-1111-1111-1111-111111111111",
                federated_credentials=[
                    FederatedCredential("main", "https://token.actions.githubusercontent.com", "repo:o/r:ref:refs/heads/main")
                ],
            )
        ],
    )
    wf = parse_workflow_text(
        "on:\n  push:\n    branches: [main]\njobs:\n  d:\n    environment: prod\n    permissions:\n      id-token: write\n"
        "    steps:\n      - uses: azure/login@v2\n        with:\n          client-id: 11111111-1111-1111-1111-111111111111\n",
        "w.yml",
    )
    diags, _ = diagnose([wf], snap, RepoInfo("o/r", created_at="2024-01-01"))
    assert diags[0].status == "no-match"
    assert any("environment subject" in h for h in diags[0].hints)


# ------------------------------------------------------------- collectors


def test_collect_azure_with_fake_runner():
    calls = []

    def run(args):
        calls.append(args)
        key = " ".join(args[:4])
        if args[:3] == ["az", "account", "show"]:
            return {"tenantId": "t", "id": "sub1"}
        if args[:3] == ["az", "identity", "list"]:
            return [{"name": "mi1", "resourceGroup": "rg", "clientId": "c1", "principalId": "p1", "id": "/x"}]
        if args[:4] == ["az", "identity", "federated-credential", "list"]:
            return [{"name": "f", "issuer": "https://token.actions.githubusercontent.com", "subject": "repo:o/r:ref:refs/heads/main", "audiences": ["api://AzureADTokenExchange"]}]
        if args[:2] == ["az", "rest"]:
            url = args[args.index("--url") + 1]
            if "/applications?" in url:
                return {"value": [{"id": "obj1", "appId": "app1", "displayName": "gh-app"}]}
            if "federatedIdentityCredentials" in url:
                return {"value": [{"name": "g", "issuer": "https://token.actions.githubusercontent.com", "subject": None, "claimsMatchingExpression": {"value": "claims['sub'] matches 'repo:o/*'", "languageVersion": 1}}]}
            if "servicePrincipals" in url:
                return {"id": "sp1"}
        if args[:3] == ["az", "role", "assignment"]:
            return [{"roleDefinitionName": "Reader", "scope": "/subscriptions/sub1"}]
        raise AssertionError(f"unexpected call {key}")

    data = collect_azure(run=run)
    assert data["tenantId"] == "t" and len(data["identities"]) == 2
    app = next(i for i in data["identities"] if i["kind"] == "app")
    assert app["federatedCredentials"][0]["claimsMatchingExpression"] == "claims['sub'] matches 'repo:o/*'"
    assert app["roleAssignments"] == [{"role": "Reader", "scope": "/subscriptions/sub1"}]
    # read-only: no create/update/delete verbs anywhere
    assert not any(v in a for a in calls for v in ("create", "delete", "update", "PUT", "PATCH", "POST"))


def test_collect_github_marks_missing_and_renamed():
    def run(args):
        if args[2] == "repos/o/gone":
            raise CollectorError("gh: Not Found (HTTP 404)")
        return {"full_name": "o/new-name", "id": 2, "owner": {"id": 1}, "created_at": "2026-08-01T00:00:00Z"}

    out = collect_github(["o/gone", "o/old-name"], run=run)
    assert out[0] == {"fullName": "o/gone", "exists": False}
    assert out[1]["renamedFrom"] == "o/old-name" and out[1]["repoId"] == 2


def test_repos_referenced_by_snapshot():
    data = json.loads((FX / "azure-snapshot.json").read_text())
    refs = repos_referenced_by_snapshot(data)
    assert "contoso/payments-api" in refs and "contoso/legacy-tool" in refs
    assert not any("*" in r for r in refs)


# ---------------------------------------------------------------- reports


def test_sarif_and_html(snapshot, inventory):
    findings = run_identity_rules(snapshot, inventory)
    sarif = json.loads(render("sarif", findings, {"version": "t", "firstWorkflow": ".github/workflows/x.yml"}))
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]
    assert all(r["locations"] for r in sarif["runs"][0]["results"])
    html = render("html", findings, {"version": "t", "identities": 4})
    assert html.startswith("<!DOCTYPE html>") and "WIA004" in html and "<script" not in html


def test_cli_fail_on_exit_code(tmp_path):
    out = tmp_path / "r.json"
    code = main(
        [
            "scan", "--azure", str(FX / "azure-snapshot.json"),
            "--repo", str(FX / "repo_main"), "--repo-slug", "contoso/payments-api",
            "--github", str(FX / "repos.json"), "--format", "json", "-o", str(out), "--fail-on", "critical",
        ]
    )
    assert code == 2
    data = json.loads(out.read_text())
    assert data["summary"]["critical"] >= 3
    assert main(["scan", "--repo", str(FX / "repo_new"), "--fail-on", "critical"]) == 0


# -------------------------------------------------------------------- mcp


def test_mcp_tools_and_server():
    from wiaudit.mcp_server import build_server, tool_doctor, tool_rules, tool_scan

    res = tool_scan(str(FX / "azure-snapshot.json"), str(FX / "repo_main"), "contoso/payments-api", str(FX / "repos.json"))
    assert res["summary"]["critical"] >= 3 and res["findings"][0]["severity"] == "critical"
    doc = tool_doctor(str(FX / "azure-snapshot.json"), str(FX / "repo_new"), "contoso/new-svc", str(FX / "repos.json"))
    assert doc["jobs"][0]["status"] == "no-match"
    assert any(r["id"] == "WIA201" for r in tool_rules())
    pytest.importorskip("mcp")
    assert build_server() is not None
