# n0s1-mcp — AI Agent Reference

> This document is optimized for AI agents invoking n0s1 tools via MCP.
> It covers the stdio MCP server interface. For CLI, Python SDK, and GitHub Actions see:
> https://github.com/spark1security/n0s1/blob/main/docs/ai.md

---

## Identity

- **Package**: `n0s1-mcp` (`spark1security/n0s1-mcp`)
- **Transport**: stdio (JSON-RPC 2.0 over stdin/stdout)
- **Purpose**: Exposes n0s1 secret-scanning capabilities as MCP tools for AI assistants (Claude Code, Claude Desktop, Cursor, etc.)
- **Underlying engine**: `n0s1.mcp_tools` — the same transport-agnostic tool functions used by the HTTP MCP server

---

## Registration

### Claude Code (user scope — available in all projects)

```bash
claude mcp add --scope user n0s1 -- uvx n0s1-mcp
```

### Claude Code (project scope)

```bash
claude mcp add --scope project n0s1 -- uvx n0s1-mcp
```

### JSON config (Claude Desktop / any MCP client)

```json
{
  "mcpServers": {
    "n0s1": {
      "command": "uvx",
      "args": ["n0s1-mcp"]
    }
  }
}
```

With pre-configured credentials:

```json
{
  "mcpServers": {
    "n0s1": {
      "command": "uvx",
      "args": ["n0s1-mcp"],
      "env": {
        "JIRA_TOKEN": "ATATT3x...",
        "JIRA_EMAIL": "user@myco.com",
        "GITHUB_TOKEN": "ghp_...",
        "N0S1_TOKEN": "n0s1_..."
      }
    }
  }
}
```

---

## Available Tools

| Tool | Required parameters | Description |
|---|---|---|
| `scan_jira` | `server`, `email`, `api_key` | Scan Jira tickets for leaked secrets |
| `scan_confluence` | `server`, `email`, `api_key` | Scan Confluence pages for leaked secrets |
| `scan_slack` | `api_key` | Scan Slack channels for leaked secrets |
| `scan_github` | `api_key`, `owner` | Scan GitHub repositories for leaked secrets |
| `scan_gitlab` | `api_key`, `owner` | Scan GitLab projects for leaked secrets |
| `scan_zendesk` | `server`, `email`, `api_key` | Scan Zendesk tickets for leaked secrets |
| `scan_linear` | `api_key` | Scan Linear issues for leaked secrets |
| `scan_asana` | `api_key` | Scan Asana tasks for leaked secrets |
| `scan_wrike` | `api_key` | Scan Wrike tasks for leaked secrets |
| `scan_local` | `scan_path` | Scan a local filesystem path for leaked secrets |
| `get_scan_status` | `report_uuid` | Return the current status of a previously started scan |
| `get_scan_findings` | `report_uuid` | Return a paginated list of findings for a completed scan |
| `analyze_report` | `report_uuid` | Submit or advance async AI credential validation for a scan |

---

## Common Optional Parameters (all `scan_*` tools except `scan_local`)

| Parameter | Type | Default | Description |
|---|---|---|---|
| `report_format` | `"n0s1"` \| `"sarif"` \| `"gitlab"` | `"n0s1"` | Output format |
| `show_matched_secret_on_logs` | bool | `false` | Include raw secret values in output |
| `ai_analysis` | bool | `false` | Queue async AI credential validation after upload (requires `n0s1_api_key` or `N0S1_TOKEN`) |
| `n0s1_api_key` | str | — | n0s1 API key; overrides `N0S1_TOKEN` env var |
| `allow_secret_upload` | bool | `false` | Upload encrypted secrets to the n0s1 backend. When `false`, credentials stay local and are injected client-side during the `waiting_client` step |

---

## Per-Tool Parameters

### `scan_jira`

| Parameter | Required | Description |
|---|---|---|
| `server` | yes | Jira server URL e.g. `https://company.atlassian.net` |
| `email` | yes | Jira user email |
| `api_key` | yes | Jira API token |
| `scope` | no | JQL query e.g. `jql:project=SEC` |
| `post_comment` | no | Auto-post warning comments on findings |

### `scan_confluence`

| Parameter | Required | Description |
|---|---|---|
| `server` | yes | Confluence server URL e.g. `https://company.atlassian.net` |
| `email` | yes | Confluence user email |
| `api_key` | yes | Confluence API token (same token as Jira) |
| `scope` | no | CQL query e.g. `cql:space=SEC and type=page` |

### `scan_slack`

| Parameter | Required | Description |
|---|---|---|
| `api_key` | yes | Slack bot token (`xoxb-...`); falls back to `SLACK_TOKEN` env var |

### `scan_github`

| Parameter | Required | Description |
|---|---|---|
| `api_key` | yes | GitHub personal access token; falls back to `GITHUB_TOKEN` |
| `owner` | yes | GitHub org or user |
| `repo` | no | Repository name (omit to scan all repos under `owner`) |
| `branch` | no | Branch to scan |
| `scope` | no | GitHub search query e.g. `search:org:myorg` |

### `scan_gitlab`

| Parameter | Required | Description |
|---|---|---|
| `api_key` | yes | GitLab personal access token; falls back to `GITLAB_TOKEN` |
| `owner` | yes | GitLab group or user |
| `server` | no | GitLab URL (default: `https://gitlab.com`) |
| `repo` | no | Project name (omit to scan all projects under `owner`) |
| `branch` | no | Branch to scan |

### `scan_zendesk`

| Parameter | Required | Description |
|---|---|---|
| `server` | yes | Zendesk subdomain e.g. `mycompany.zendesk.com` |
| `email` | yes | Zendesk user email |
| `api_key` | yes | Zendesk API token |

### `scan_linear`

| Parameter | Required | Description |
|---|---|---|
| `api_key` | yes | Linear API key (`lin_api_...`); falls back to `LINEAR_TOKEN` |

### `scan_asana`

| Parameter | Required | Description |
|---|---|---|
| `api_key` | yes | Asana personal access token; falls back to `ASANA_TOKEN` |
| `scope` | no | Workspace or project scope filter |

### `scan_wrike`

| Parameter | Required | Description |
|---|---|---|
| `api_key` | yes | Wrike permanent access token; falls back to `WRIKE_TOKEN` |
| `scope` | no | Folder or space scope filter |

### `scan_local`

| Parameter | Required | Description |
|---|---|---|
| `scan_path` | yes | Absolute or relative path to scan |
| `regex_file` | no | Path to custom regex YAML file |
| `report_format` | no | `"n0s1"` \| `"sarif"` \| `"gitlab"` (default: `"n0s1"`) |
| `show_matched_secret_on_logs` | no | Include raw secret values in output |

`scan_local` does not support `ai_analysis`, `n0s1_api_key`, or `allow_secret_upload`.

### `get_scan_status`

| Parameter | Required | Description |
|---|---|---|
| `report_uuid` | yes | UUID returned by the originating `scan_*` call |

### `get_scan_findings`

| Parameter | Required | Description |
|---|---|---|
| `report_uuid` | yes | UUID returned by the originating `scan_*` call |
| `page` | no | Opaque cursor from a previous response (omit for first page) |
| `severity` | no | Filter: `info` \| `low` \| `medium` \| `high` \| `critical` |

### `analyze_report`

| Parameter | Required | Description |
|---|---|---|
| `report_uuid` | yes | UUID returned by a `scan_*` tool or a previous `analyze_report` call |
| `n0s1_api_key` | no | n0s1 API key; overrides `N0S1_TOKEN` env var |
| `report_file` | no | Path to local report JSON file — required when status is `waiting_client` |
| `wait_minutes` | no | Poll every 30 s until a terminal state or this many minutes elapse. Returns `ai_analysis_status='timeout'` if the deadline is reached |

---

## Environment Variables

Credentials are read from environment variables when not passed as tool arguments.

| Variable | Used by |
|---|---|
| `N0S1_TOKEN` | All tools with `n0s1_api_key` — Professional mode uploads and AI analysis |
| `JIRA_TOKEN` | `scan_jira`, `scan_confluence` |
| `JIRA_EMAIL` | `scan_jira`, `scan_confluence` |
| `SLACK_TOKEN` | `scan_slack` |
| `GITHUB_TOKEN` | `scan_github` |
| `GITLAB_TOKEN` | `scan_gitlab` |
| `ZENDESK_TOKEN` | `scan_zendesk` |
| `ZENDESK_EMAIL` | `scan_zendesk` |
| `LINEAR_TOKEN` | `scan_linear` |
| `ASANA_TOKEN` | `scan_asana` |
| `WRIKE_TOKEN` | `scan_wrike` |

---

## Return Value Schema

Every `scan_*` tool returns a `ScanResult`:

```json
{
  "report_uuid": "3f8a...",
  "status": "complete",
  "summary": {
    "total_findings": 3,
    "by_severity": {"high": 3},
    "by_type": {"aws-access-key": 2, "github-pat": 1}
  },
  "findings": [
    {
      "file": "https://...",
      "line": 42,
      "type": "aws-access-key",
      "severity": "high",
      "redacted_match": "AKIA****MPLE"
    }
  ],
  "usage": {
    "tokens_in_estimate": 5000,
    "tokens_out_actual": 200,
    "tokens_saved_estimate": 4800,
    "savings_pct": 96.0
  }
}
```

`get_scan_status` returns a lightweight `Status`:

```json
{"report_uuid": "...", "status": "complete", "progress_pct": 100.0, "error": null}
```

`get_scan_findings` returns a paginated `FindingsPage` (50 findings per page):

```json
{
  "report_uuid": "...",
  "findings": [...],
  "next_cursor": "<opaque string>",
  "total": 150,
  "usage": {...}
}
```

`analyze_report` returns an `AnalysisStatus`:

```json
{
  "report_uuid": "...",
  "ai_analysis_status": "complete",
  "findings_count": 3,
  "validated_count": 2
}
```

`ai_analysis_status` values: `pending` → `waiting_client` → `pending_verdict` → `complete` | `failed` | `timeout`

---

## AI Analysis Workflow

AI analysis validates whether detected credentials are actually live. It requires an n0s1 Professional token (`N0S1_TOKEN` env var or `n0s1_api_key` parameter).

### Option A — blocking (single tool call)

Pass `ai_analysis: true` and `wait_minutes: 10` on the scan tool. The call blocks until analysis completes or the timeout elapses.

```
scan_jira(server=..., email=..., api_key=..., n0s1_api_key=..., ai_analysis=true, wait_minutes=10)
→ ScanResult with ai_analysis_status="complete"
```

### Option B — polling (separate calls)

```
# Step 1: scan and queue analysis
scan_jira(server=..., email=..., api_key=..., n0s1_api_key=..., ai_analysis=true)
→ ScanResult { report_uuid: "abc123", status: "complete" }

# Step 2: advance analysis (repeat until terminal state)
analyze_report(report_uuid="abc123")
→ AnalysisStatus { ai_analysis_status: "waiting_client" }

# Step 3: when status is "waiting_client", pass report_file
analyze_report(report_uuid="abc123", report_file="/path/to/report.json")
→ AnalysisStatus { ai_analysis_status: "pending_verdict" }

# Step 4: repeat until complete
analyze_report(report_uuid="abc123")
→ AnalysisStatus { ai_analysis_status: "complete" }
```

### `allow_secret_upload`

By default (`allow_secret_upload: false`) encrypted secrets are never sent to the backend — they stay local and are injected into HTTP validators during the `waiting_client` step. Set `allow_secret_upload: true` to upload the encrypted payloads for fully server-side validation.

---

## Scope Query Language

The `scope` parameter filters what gets scanned:

| Prefix | Platform | Example |
|---|---|---|
| `jql:` | Jira | `jql:project=SEC AND status=Open` |
| `cql:` | Confluence | `cql:space=SEC and type=page` |
| `search:` | GitHub / GitLab | `search:org:myorg language:python` |

---

## Key Files

| File | Purpose |
|---|---|
| `n0s1_mcp_server.py` | stdio MCP server — tool definitions and handlers |
| `docs/ai.md` | This file |
| `README.md` | Human-oriented setup guide |
