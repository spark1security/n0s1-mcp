<!-- mcp-name: io.github.spark1security/n0s1-mcp -->
# n0s1-mcp

An [MCP](https://modelcontextprotocol.io/) server that exposes [n0s1](https://github.com/spark1security/n0s1) secret-scanning capabilities as tools for AI assistants (Claude, Cursor, etc.).

Scan Jira, Confluence, Slack, GitHub, GitLab, Zendesk, Linear, Asana, Wrike, and local filesystems for leaked secrets — directly from your AI workflow.

## Quickstart

No install required. Add this to your MCP client config and run via `uvx`:

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

For Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json`  
For Claude Code: `.claude/mcp.json` in your project, or `~/.claude/mcp.json` globally.

## Available Tools

| Tool | Description | Required params |
|------|-------------|-----------------|
| `scan_jira` | Scan Jira tickets | `server`, `email`, `api_key` |
| `scan_confluence` | Scan Confluence pages | `server`, `email`, `api_key` |
| `scan_slack` | Scan Slack channels | `api_key` |
| `scan_github` | Scan GitHub repositories | `api_key`, `owner` |
| `scan_gitlab` | Scan GitLab projects | `api_key`, `owner` |
| `scan_zendesk` | Scan Zendesk tickets | `server`, `email`, `api_key` |
| `scan_linear` | Scan Linear issues | `api_key` |
| `scan_asana` | Scan Asana tasks | `api_key` |
| `scan_wrike` | Scan Wrike tasks | `api_key` |
| `scan_local` | Scan local filesystem | `scan_path` |
| `get_scan_status` | Get status of a running/completed scan | `report_uuid` |
| `get_scan_findings` | Get paginated findings for a completed scan | `report_uuid` |
| `analyze_report` | Submit or advance async AI credential validation | `report_uuid` |

All `scan_*` tools accept these optional parameters:

| Parameter | Description |
|---|---|
| `report_uuid` | UUID to assign to the scan report. When set, overrides the auto-generated UUID written to the report JSON. |
| `ai_analysis` | Queue async AI credential validation after the scan (requires n0s1 Professional) |
| `n0s1_api_key` | n0s1 API key; overrides `N0S1_TOKEN` env var |
| `allow_secret_upload` | Allow encrypted secrets to be uploaded to the n0s1 backend (default: `false`) |

Pass `wait_minutes` to `analyze_report` (or directly on a scan tool alongside `ai_analysis`) to block until analysis completes.

## Environment Variables

Credentials can be passed as tool arguments or pre-set as environment variables:

| Variable | Used by |
|----------|---------|
| `N0S1_TOKEN` | All scan tools with `ai_analysis` — Professional mode uploads and AI analysis |
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

Example with env vars pre-configured:

```json
{
  "mcpServers": {
    "n0s1": {
      "command": "uvx",
      "args": ["n0s1-mcp"],
      "env": {
        "GITHUB_TOKEN": "ghp_...",
        "JIRA_TOKEN": "ATATT..."
      }
    }
  }
}
```

## Usage Examples

Once connected, ask your AI assistant:

- *"Scan my Jira project SEC for leaked secrets"*
- *"Check the GitHub org mycompany for exposed API keys"*
- *"Scan the /home/user/project directory for secrets"*
- *"Run an AI analysis on the scan report abc123"*

For full parameter reference and AI analysis workflow details, see [docs/ai.md](docs/ai.md).

## Publishing to PyPI

```bash
pip install hatch
hatch build
hatch publish
```

## License

GNU General Public License v3 — same as [n0s1](https://github.com/spark1security/n0s1).
