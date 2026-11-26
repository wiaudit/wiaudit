# wiaudit — Workload Identity Auditor for GitHub Actions → Azure

> **Alpha.** Tested on a large production tenant. Feedback and issues welcome.

**Fix `AADSTS700213` and find risky OIDC trust between GitHub Actions and Azure / Microsoft Entra ID.**

```text
AADSTS700213: No matching federated identity record found for presented assertion subject
'repo:my-org/my-repo:ref:refs/heads/main'
```

`wiaudit doctor` tells you, for every job that uses `azure/login`, which subject GitHub will send,
whether any federated credential accepts it, and why not (environment vs branch subject, missing
`id-token: write`, the new immutable `owner@id/repo@id` format, case mismatch, renamed repo).
`wiaudit scan` audits every federated credential in the tenant and reports risky trust.

```bash
pip install wiaudit
az login
wiaudit collect azure -o azure-snapshot.json --all-subscriptions
wiaudit doctor --azure azure-snapshot.json          # run inside your repo
wiaudit scan   --azure azure-snapshot.json --format html -o report.html
```

**Typical findings on a real tenant:** federated credentials that trust repos on *personal* GitHub
accounts, wildcard (flexible) credentials without `repository_id`, `pull_request` trust on identities
with Contributor/Owner, trust to deleted or renamed repos, identities at the 20-credential limit.

- **Read-only.** Collectors only list things (`az … list`, Graph `GET`, `gh api` `GET`). wiaudit never
  creates, changes or deletes anything and never handles credentials — it uses your existing `az` / `gh` login.
- **Offline analysis.** Collection writes plain JSON; `scan` and `doctor` work on those files, so you
  can collect in one place and analyse anywhere (or hand the JSON to an auditor).
- **Fast on large tenants:** apps are filtered server-side (only those trusting GitHub), one role-assignment
  query per subscription, automatic retries.
- Outputs: terminal, **HTML**, **JSON**, **SARIF** (GitHub code scanning). CI exit codes.
- **GitHub Action** for CI and a local **MCP server** (`wiaudit-mcp`), so coding agents
  (Claude Code, GitHub Copilot, Cursor) can diagnose Azure login failures for you.

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
             --repo ./my-repo --format html -o report.html \
             --allowed-owners my-org,my-other-org      # optional: flag every other owner

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
| WIA009 | low | Credential from an unrecognised issuer (`collect azure --all-issuers`) |
| WIA010 | medium–critical | Trust to a repo outside your organizations: owner not in `--allowed-owners`, or a personal GitHub account |
| WIA011 | info | Review list of all GitHub owners trusted in the tenant |
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

## FAQ

**How do I fix `AADSTS700213: No matching federated identity record found`?**
Run `wiaudit doctor` in the repository. It prints the exact subject GitHub sends and the closest
credential, e.g. the job has `environment: prod` so the subject is `repo:org/repo:environment:prod`,
not `…:ref:refs/heads/main`. Add a federated credential with that exact subject (matching is exact
and case-sensitive).

**`azure/login` with OIDC stopped working for a new or renamed repo.**
Since 2026‑07‑15 GitHub sends the immutable subject `repo:OWNER@OWNER_ID/REPO@REPO_ID:…` for repos
created, renamed or transferred after that date. Credentials written as `repo:OWNER/REPO:…` no longer
match. `wiaudit doctor` detects this and shows the subject to use.

**Which federated credentials in my tenant are risky?**
`wiaudit scan --azure azure-snapshot.json --allowed-owners my-org` lists credentials that trust
repos outside your organizations (personal accounts), wildcards without `repository_id`,
`pull_request` trust, dangling repos and privileged roles.

**Does it need admin rights?** No. Reader on the subscriptions and the default ability to read
app registrations in Entra ID are enough. Nothing is modified.

**Is my data sent anywhere?** No. Everything runs locally; there is no telemetry.

## Commercial support

Need a one-off audit of your tenant with a remediation plan, organization-wide scanning, or
compliance reports (NIS2 / ISO 27001)? Open a
[GitHub Discussion](https://github.com/wiaudit/wiaudit/discussions) or an issue with the label
`commercial`.

## Limits (v0.1)

- GitHub Actions → Azure only (GitLab, Azure DevOps, AWS/GCP planned).
- Custom OIDC subject templates (`gh api repos/…/actions/oidc/customization/sub`) are not yet modelled.
- Reusable workflows (`job_workflow_ref`) are not yet resolved.

Scan only tenants and repositories you are authorised to assess.

License: Apache‑2.0

<!-- mcp-name: io.github.wiaudit/wiaudit -->
