# wiaudit — Workload Identity Auditor

> **Alpha (0.1).** Feedback and issues welcome.

Find risky **GitHub Actions → Azure / Microsoft Entra OIDC trust**, and see exactly why a workflow
gets `AADSTS700213: No matching federated identity record found`.

- **Read-only.** Collectors only list things (`az … list`, Graph `GET`, `gh api` `GET`). wiaudit never
  creates, changes or deletes anything and never handles credentials — it uses your existing `az` / `gh` login.
- **Offline analysis.** Collection writes plain JSON; `scan` and `doctor` work on those files, so you
  can collect in one place and analyse anywhere (or hand the JSON to an auditor).
- Outputs: terminal, **HTML**, **JSON**, **SARIF** (GitHub code scanning). CI exit codes.
- Also ships a local **MCP server**, so coding agents (Claude Code, Copilot, Cursor) can run the audit.

## Why now

- GitHub now issues **immutable OIDC subjects** (`repo:OWNER@OWNER_ID/REPO@REPO_ID:…`) for repositories
  created, renamed or transferred on/after **2026‑07‑15**. Federated credentials written in the old
  name‑based format silently stop matching for those repos, and Microsoft recommends migrating.
- Name‑based trust to a **deleted or renamed** repo can be claimed by whoever registers that name again.
- CI identities often hold **Owner / Contributor on a whole subscription** and trust `pull_request` runs.

## Install

```bash
pip install wiaudit
# latest from GitHub:
pip install git+https://github.com/wiaudit/wiaudit.git
pip install "wiaudit[mcp]"     # + MCP server
```

Requires Python 3.10+, and for collection: Azure CLI (`az login`) and GitHub CLI (`gh auth login`).

## Quick start

```bash
az login
wiaudit collect azure -o azure-snapshot.json                 # current subscription
#   --all-subscriptions | --subscription <id> (repeat) | --app-prefix gh- | --no-apps | --no-managed-identities
wiaudit collect github --from-azure azure-snapshot.json -o repos.json   # repo IDs, created date, deleted/renamed

wiaudit scan --azure azure-snapshot.json --github repos.json \
             --repo ./my-repo --format html -o report.html

cd my-repo && wiaudit doctor --azure ../azure-snapshot.json --github ../repos.json
```

Permissions needed to collect: Azure **Reader** on the subscriptions, and in Entra the ability to read
applications (any member user can by default; `Application.Read.All` for service principals).

### `doctor` output

```
[FAIL] .github/workflows/deploy.yml -> job 'deploy'
       identity: managedIdentity:mi-new-svc (2222…)
       REJECTED: repo:contoso@5544123/new-svc@900001:ref:refs/heads/main
       closest credential subject: repo:contoso/new-svc:ref:refs/heads/main
       hint: This repo was created, renamed or transferred on/after 2026-07-15, so GitHub sends the
             immutable subject … The name-based credentials will not match.
```

## Rules

| ID | Severity* | Finding |
|----|-----------|---------|
| WIA001 | low–high | Name‑based (mutable) GitHub subject; suggests the immutable subject when IDs are known |
| WIA002 | high | Flexible credential with wildcards that does not bind `repository_id` / `repository_owner_id` |
| WIA003 | medium–critical | Identity trusts `pull_request` runs |
| WIA004 | medium–high | Privileged role (Owner, UAA, RBAC Admin, Contributor) at subscription / MG / root scope |
| WIA005 | low | Non‑default audience |
| WIA006 | critical | Trust to a GitHub repo that no longer exists (name can be re‑registered) |
| WIA007 | critical | Trust to a repo's old name after a rename |
| WIA008 | medium | Identity near the 20 federated credentials limit |
| WIA009 | low | Credential from an unrecognised issuer |
| WIA101 | critical | `pull_request_target` workflow with `id-token: write` |
| WIA102 | low | `id-token: write` granted at workflow level to several jobs |
| WIA103 | medium | `azure/login` with a long‑lived `creds:` secret instead of OIDC |
| WIA104 | medium | `azure/login` OIDC step without `id-token: write` |
| WIA201 | high | A workflow job's subject matches no federated credential (would fail at login) |

\* Severity is raised when the identity holds privileged roles. `wiaudit rules` lists them.

## CI: GitHub Action

```yaml
permissions:
  contents: read
  security-events: write
jobs:
  wiaudit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: wiaudit/wiaudit@v0
        with:
          fail-on: critical
          # azure-snapshot: audit/azure-snapshot.json   # optional, or collect-azure: true after azure/login
```

Without a snapshot the action checks workflows only (WIA101–104). Findings appear in the Security tab.

## MCP server (for AI coding agents)

```json
{ "mcpServers": { "wiaudit": { "command": "wiaudit-mcp" } } }
```

Tools: `scan`, `doctor`, `list_rules` — all read‑only, local files only.

## Snapshot format

`azure-snapshot.json` (v1): `{ version, tenantId, identities: [{ kind: app|managedIdentity, displayName,
clientId, objectId, resourceId?, federatedCredentials: [{ name, issuer, subject, audiences,
claimsMatchingExpression? }], roleAssignments: [{ role, scope }] }] }`. You can generate it yourself
(e.g. from Terraform state) and still use `scan` / `doctor`.

## Limits (v0.1)

- GitHub Actions → Azure only (GitLab, Azure DevOps, AWS/GCP planned).
- Custom OIDC subject templates (`gh api repos/…/actions/oidc/customization/sub`) are not yet modelled.
- Reusable workflows (`job_workflow_ref`) are not yet resolved.

Scan only tenants and repositories you are authorised to assess.

License: Apache‑2.0
