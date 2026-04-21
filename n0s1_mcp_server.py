import os
import asyncio
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

try:
    import scanner
except ImportError:
    import n0s1.scanner as scanner

app = Server("n0s1")

# ─── Tool definitions ────────────────────────────────────────────────────────

@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="scan_jira",
            description="Scan Jira tickets for leaked secrets",
            inputSchema={
                "type": "object",
                "properties": {
                    "server":        {"type": "string", "description": "Jira server URL e.g. https://company.atlassian.net"},
                    "email":         {"type": "string", "description": "Jira user email"},
                    "api_key":       {"type": "string", "description": "Jira API token"},
                    "scope":         {"type": "string", "description": "JQL query e.g. jql:project = SEC"},
                    "post_comment":  {"type": "boolean", "description": "Auto-post warning comments on findings"},
                    "report_format": {"type": "string", "enum": ["n0s1", "sarif", "gitlab"], "default": "n0s1"},
                    "show_matched_secret_on_logs": {"type": "boolean", "description": "Show matched secret values in reports and logs (default: false)"},
                },
                "required": ["server", "email", "api_key"],
            },
        ),
        Tool(
            name="scan_confluence",
            description="Scan Confluence pages for leaked secrets",
            inputSchema={
                "type": "object",
                "properties": {
                    "server":        {"type": "string", "description": "Confluence server URL e.g. https://company.atlassian.net"},
                    "email":         {"type": "string", "description": "Confluence user email"},
                    "api_key":       {"type": "string", "description": "Confluence API token"},
                    "scope":         {"type": "string", "description": "CQL query e.g. cql:space=SEC and type=page"},
                    "report_format": {"type": "string", "enum": ["n0s1", "sarif", "gitlab"], "default": "n0s1"},
                    "show_matched_secret_on_logs": {"type": "boolean", "description": "Show matched secret values in reports and logs (default: false)"},
                },
                "required": ["server", "email", "api_key"],
            },
        ),
        Tool(
            name="scan_slack",
            description="Scan Slack channels for leaked secrets",
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key":       {"type": "string", "description": "Slack bot token (xoxb-...)"},
                    "report_format": {"type": "string", "enum": ["n0s1", "sarif", "gitlab"], "default": "n0s1"},
                    "show_matched_secret_on_logs": {"type": "boolean", "description": "Show matched secret values in reports and logs (default: false)"},
                },
                "required": ["api_key"],
            },
        ),
        Tool(
            name="scan_github",
            description="Scan GitHub repositories for leaked secrets",
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key": {"type": "string", "description": "GitHub personal access token"},
                    "owner":   {"type": "string", "description": "GitHub org or user"},
                    "repo":    {"type": "string", "description": "Repository name (optional, scans all repos if omitted)"},
                    "branch":  {"type": "string", "description": "Branch to scan (optional)"},
                    "scope":   {"type": "string", "description": "Search query e.g. search:org:myorg"},
                    "report_format": {"type": "string", "enum": ["n0s1", "sarif", "gitlab"], "default": "n0s1"},
                    "show_matched_secret_on_logs": {"type": "boolean", "description": "Show matched secret values in reports and logs (default: false)"},
                },
                "required": ["api_key", "owner"],
            },
        ),
        Tool(
            name="scan_gitlab",
            description="Scan GitLab projects for leaked secrets",
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key": {"type": "string", "description": "GitLab personal access token"},
                    "server":  {"type": "string", "description": "GitLab server URL (default: https://gitlab.com)"},
                    "owner":   {"type": "string", "description": "GitLab group or user"},
                    "repo":    {"type": "string", "description": "Project name (optional, scans all if omitted)"},
                    "branch":  {"type": "string", "description": "Branch to scan (optional)"},
                    "report_format": {"type": "string", "enum": ["n0s1", "sarif", "gitlab"], "default": "n0s1"},
                    "show_matched_secret_on_logs": {"type": "boolean", "description": "Show matched secret values in reports and logs (default: false)"},
                },
                "required": ["api_key", "owner"],
            },
        ),
        Tool(
            name="scan_zendesk",
            description="Scan Zendesk tickets for leaked secrets",
            inputSchema={
                "type": "object",
                "properties": {
                    "server":  {"type": "string", "description": "Zendesk subdomain e.g. mycompany.zendesk.com"},
                    "email":   {"type": "string", "description": "Zendesk user email"},
                    "api_key": {"type": "string", "description": "Zendesk API token"},
                    "report_format": {"type": "string", "enum": ["n0s1", "sarif", "gitlab"], "default": "n0s1"},
                    "show_matched_secret_on_logs": {"type": "boolean", "description": "Show matched secret values in reports and logs (default: false)"},
                },
                "required": ["server", "email", "api_key"],
            },
        ),
        Tool(
            name="scan_linear",
            description="Scan Linear issues for leaked secrets",
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key": {"type": "string", "description": "Linear API key (lin_api_...)"},
                    "report_format": {"type": "string", "enum": ["n0s1", "sarif", "gitlab"], "default": "n0s1"},
                    "show_matched_secret_on_logs": {"type": "boolean", "description": "Show matched secret values in reports and logs (default: false)"},
                },
                "required": ["api_key"],
            },
        ),
        Tool(
            name="scan_asana",
            description="Scan Asana tasks for leaked secrets",
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key": {"type": "string", "description": "Asana personal access token"},
                    "scope":   {"type": "string", "description": "Workspace or project scope filter"},
                    "report_format": {"type": "string", "enum": ["n0s1", "sarif", "gitlab"], "default": "n0s1"},
                    "show_matched_secret_on_logs": {"type": "boolean", "description": "Show matched secret values in reports and logs (default: false)"},
                },
                "required": ["api_key"],
            },
        ),
        Tool(
            name="scan_wrike",
            description="Scan Wrike tasks for leaked secrets",
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key": {"type": "string", "description": "Wrike permanent access token"},
                    "scope":   {"type": "string", "description": "Folder or space scope filter"},
                    "report_format": {"type": "string", "enum": ["n0s1", "sarif", "gitlab"], "default": "n0s1"},
                    "show_matched_secret_on_logs": {"type": "boolean", "description": "Show matched secret values in reports and logs (default: false)"},
                },
                "required": ["api_key"],
            },
        ),
        Tool(
            name="scan_local",
            description="Scan a local filesystem path for leaked secrets",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_path":     {"type": "string", "description": "Absolute or relative path to scan"},
                    "regex_file":    {"type": "string", "description": "Path to custom regex YAML file (optional)"},
                    "report_format": {"type": "string", "enum": ["n0s1", "sarif", "gitlab"], "default": "n0s1"},
                    "show_matched_secret_on_logs": {"type": "boolean", "description": "Show matched secret values in reports and logs (default: false)"},
                },
                "required": ["scan_path"],
            },
        ),
    ]

# ─── Shared scan runner ───────────────────────────────────────────────────────

_TARGET_MAP = {
    "scan_jira":       "jira_scan",
    "scan_confluence": "confluence_scan",
    "scan_slack":      "slack_scan",
    "scan_github":     "github_scan",
    "scan_gitlab":     "gitlab_scan",
    "scan_zendesk":    "zendesk_scan",
    "scan_linear":     "linear_scan",
    "scan_asana":      "asana_scan",
    "scan_wrike":      "wrike_scan",
    "scan_local":      "local_scan",
}

_ENV_MAP = {
    "jira_scan":       "JIRA_TOKEN",
    "confluence_scan": "JIRA_TOKEN",
    "slack_scan":      "SLACK_TOKEN",
    "github_scan":     "GITHUB_TOKEN",
    "gitlab_scan":     "GITLAB_TOKEN",
    "zendesk_scan":    "ZENDESK_TOKEN",
    "linear_scan":     "LINEAR_TOKEN",
    "asana_scan":      "ASANA_TOKEN",
    "wrike_scan":      "WRIKE_TOKEN",
}


def run_scan(target: str, **kwargs) -> str:
    s = scanner.SecretScanner(target=target, **kwargs)
    result = s.scan()

    if not result:
        return "Scan completed. No findings."

    findings = result.get("findings", {})
    tool_info = result.get("tool", {})
    scan_date = result.get("scan_date", {}).get("date_utc", "unknown")

    lines = [
        f"n0s1 v{tool_info.get('version', '?')} scan complete",
        f"Target: {target}",
        f"Date: {scan_date}",
        f"Total findings: {len(findings)}",
        "",
    ]
    for finding in findings.values():
        ticket = finding.get("ticket_data", {})
        lines.append(f"• {ticket.get('issue_id', '?')} [{ticket.get('field', '?')}] — {ticket.get('url', '')}")
        for match in finding.get("matches", []):
            lines.append(f"    Pattern: {match.get('pattern_name')} | Secret: {match.get('sanitized_secret')}")

    return "\n".join(lines)

# ─── Tool handlers ────────────────────────────────────────────────────────────

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        target = _TARGET_MAP.get(name)
        if not target:
            raise ValueError(f"Unknown tool: {name}")

        if "api_key" not in arguments:
            env_key = _ENV_MAP.get(target)
            token = env_key and os.getenv(env_key)
            if token:
                arguments["api_key"] = token

        text = await asyncio.to_thread(run_scan, target, **arguments)
        return [TextContent(type="text", text=text)]

    except Exception as e:
        return [TextContent(type="text", text=f"Error running {name}: {e}")]

# ─── Entry point ──────────────────────────────────────────────────────────────

async def _async_main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


def main():
    asyncio.run(_async_main())


if __name__ == "__main__":
    main()
