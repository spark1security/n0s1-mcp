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

## Environment Variables

Credentials can be passed as tool arguments or pre-set as environment variables:

| Variable | Used by |
|----------|---------|
| `JIRA_TOKEN` | `scan_jira`, `scan_confluence` |
| `SLACK_TOKEN` | `scan_slack` |
| `GITHUB_TOKEN` | `scan_github` |
| `GITLAB_TOKEN` | `scan_gitlab` |
| `ZENDESK_TOKEN` | `scan_zendesk` |
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

## Publishing to PyPI

```bash
pip install hatch
hatch build
hatch publish
```

## License

GNU General Public License v3 — same as [n0s1](https://github.com/spark1security/n0s1).
