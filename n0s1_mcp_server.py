import asyncio
import json
import os
import uuid

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from n0s1.mcp_tools import (
    Finding,
    FindingsPage,
    ScanResult,
    ScanSummary,
    Severity,
    Status,
    ToolContext,
    Usage,
    get_scan_findings,
    get_scan_status,
    redact_match,
    scan_asana,
    scan_confluence,
    scan_github,
    scan_gitlab,
    scan_jira,
    scan_linear,
    scan_slack,
    scan_wrike,
    scan_zendesk,
    usage_block,
)

try:
    import scanner as _scanner
except ImportError:
    import n0s1.scanner as _scanner

app = Server("n0s1")

# ─── stdio ToolContext factory ────────────────────────────────────────────────

def stdio_context() -> ToolContext:
    return ToolContext(
        user_id=None,
        token_id=None,
        agent_session_id=None,
        runner=os.getenv("RUNNER_ENV", "DOCKER"),
        on_scan_event=None,
    )

# ─── Local scan helper (scan_local is not in the shared spec) ────────────────

def _run_local_scan(
    scan_path: str,
    regex_file: str | None = None,
    report_format: str = "n0s1",
    show_matched_secret_on_logs: bool = False,
) -> ScanResult:
    report_uuid = str(uuid.uuid4())
    kwargs: dict = {
        "scan_path": scan_path,
        "show_matched_secret_on_logs": show_matched_secret_on_logs,
        "post_comment": False,
        "report_format": report_format,
    }
    if regex_file:
        kwargs["regex_file"] = regex_file

    try:
        s = _scanner.SecretScanner(target="local_scan", **kwargs)
        report_json = s.scan()
        sensitive_json = s.report_sensitive_json

        findings_list: list[Finding] = []
        for fid, f in (report_json.get("findings") or {}).items():
            matched_cfg = f.get("details", {}).get("matched_regex_config") or {}
            secret_type = matched_cfg.get("id", "unknown")
            raw = ""
            if sensitive_json:
                raw = sensitive_json.get("findings", {}).get(fid, {}).get("sensitive_secret", "")
            if not raw:
                raw = f.get("mocked_secret", "") or f.get("secret", "")
            url = f.get("url", "")
            line_number = None
            if "#L" in url:
                try:
                    line_number = int(url.split("#L")[-1])
                except (ValueError, IndexError):
                    pass
            findings_list.append(Finding(
                file=url,
                line=line_number,
                type=secret_type,
                severity=Severity.high,
                redacted_match=redact_match(str(raw), secret_type),
            ))

        by_severity: dict[Severity, int] = {}
        by_type: dict[str, int] = {}
        for finding in findings_list:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_type[finding.type] = by_type.get(finding.type, 0) + 1

        summary = ScanSummary(
            total_findings=len(findings_list),
            by_severity=by_severity,
            by_type=by_type,
        )
        use = usage_block({"scan_path": scan_path}, report_json)
        return ScanResult(
            report_uuid=report_uuid,
            status="complete",
            summary=summary,
            findings=findings_list,
            usage=use,
        )
    except Exception as exc:
        return ScanResult(
            report_uuid=report_uuid,
            status="failed",
            summary=ScanSummary(total_findings=0, by_severity={}, by_type={}),
            usage=Usage(
                tokens_in_estimate=0,
                tokens_out_actual=0,
                tokens_saved_estimate=0,
                savings_pct=0.0,
            ),
        )

# ─── Tool definitions ─────────────────────────────────────────────────────────

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
        Tool(
            name="get_scan_status",
            description="Return the current status of a previously started scan",
            inputSchema={
                "type": "object",
                "properties": {
                    "report_uuid": {"type": "string", "description": "UUID returned by the originating scan_* call"},
                },
                "required": ["report_uuid"],
            },
        ),
        Tool(
            name="get_scan_findings",
            description="Return a paginated list of findings for a completed scan",
            inputSchema={
                "type": "object",
                "properties": {
                    "report_uuid": {"type": "string", "description": "UUID returned by the originating scan_* call"},
                    "page":     {"type": "string", "description": "Opaque cursor from a previous response (omit for first page)"},
                    "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"], "description": "Filter findings to this severity level"},
                },
                "required": ["report_uuid"],
            },
        ),
    ]

# ─── Tool handlers ────────────────────────────────────────────────────────────

def _json_text(model) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(model.model_dump(mode="json")))]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        ctx = stdio_context()

        if name == "scan_jira":
            result = await asyncio.to_thread(
                scan_jira,
                workspace_url=arguments["server"],
                scope=arguments.get("scope"),
                api_key=arguments.get("api_key") or os.getenv("JIRA_TOKEN"),
                email=arguments.get("email") or os.getenv("JIRA_EMAIL"),
                report_format=arguments.get("report_format", "n0s1"),
                show_matched_secret_on_logs=arguments.get("show_matched_secret_on_logs", False),
                ctx=ctx,
            )
            return _json_text(result)

        elif name == "scan_confluence":
            result = await asyncio.to_thread(
                scan_confluence,
                workspace_url=arguments["server"],
                scope=arguments.get("scope"),
                api_key=arguments.get("api_key") or os.getenv("JIRA_TOKEN"),
                email=arguments.get("email") or os.getenv("JIRA_EMAIL"),
                report_format=arguments.get("report_format", "n0s1"),
                show_matched_secret_on_logs=arguments.get("show_matched_secret_on_logs", False),
                ctx=ctx,
            )
            return _json_text(result)

        elif name == "scan_slack":
            result = await asyncio.to_thread(
                scan_slack,
                api_key=arguments.get("api_key") or os.getenv("SLACK_TOKEN"),
                report_format=arguments.get("report_format", "n0s1"),
                show_matched_secret_on_logs=arguments.get("show_matched_secret_on_logs", False),
                ctx=ctx,
            )
            return _json_text(result)

        elif name == "scan_github":
            owner = arguments["owner"]
            repo_name = arguments.get("repo", "")
            combined = f"{owner}/{repo_name}" if repo_name else owner
            result = await asyncio.to_thread(
                scan_github,
                repo=combined,
                branch=arguments.get("branch"),
                scope=arguments.get("scope"),
                api_key=arguments.get("api_key") or os.getenv("GITHUB_TOKEN"),
                report_format=arguments.get("report_format", "n0s1"),
                show_matched_secret_on_logs=arguments.get("show_matched_secret_on_logs", False),
                ctx=ctx,
            )
            return _json_text(result)

        elif name == "scan_gitlab":
            owner = arguments["owner"]
            repo_name = arguments.get("repo", "")
            combined = f"{owner}/{repo_name}" if repo_name else owner
            result = await asyncio.to_thread(
                scan_gitlab,
                repo=combined,
                server=arguments.get("server"),
                branch=arguments.get("branch"),
                api_key=arguments.get("api_key") or os.getenv("GITLAB_TOKEN"),
                report_format=arguments.get("report_format", "n0s1"),
                show_matched_secret_on_logs=arguments.get("show_matched_secret_on_logs", False),
                ctx=ctx,
            )
            return _json_text(result)

        elif name == "scan_zendesk":
            result = await asyncio.to_thread(
                scan_zendesk,
                workspace_url=arguments["server"],
                api_key=arguments.get("api_key") or os.getenv("ZENDESK_TOKEN"),
                email=arguments.get("email") or os.getenv("ZENDESK_EMAIL"),
                report_format=arguments.get("report_format", "n0s1"),
                show_matched_secret_on_logs=arguments.get("show_matched_secret_on_logs", False),
                ctx=ctx,
            )
            return _json_text(result)

        elif name == "scan_linear":
            result = await asyncio.to_thread(
                scan_linear,
                api_key=arguments.get("api_key") or os.getenv("LINEAR_TOKEN"),
                report_format=arguments.get("report_format", "n0s1"),
                show_matched_secret_on_logs=arguments.get("show_matched_secret_on_logs", False),
                ctx=ctx,
            )
            return _json_text(result)

        elif name == "scan_asana":
            result = await asyncio.to_thread(
                scan_asana,
                scope=arguments.get("scope"),
                api_key=arguments.get("api_key") or os.getenv("ASANA_TOKEN"),
                report_format=arguments.get("report_format", "n0s1"),
                show_matched_secret_on_logs=arguments.get("show_matched_secret_on_logs", False),
                ctx=ctx,
            )
            return _json_text(result)

        elif name == "scan_wrike":
            result = await asyncio.to_thread(
                scan_wrike,
                scope=arguments.get("scope"),
                api_key=arguments.get("api_key") or os.getenv("WRIKE_TOKEN"),
                report_format=arguments.get("report_format", "n0s1"),
                show_matched_secret_on_logs=arguments.get("show_matched_secret_on_logs", False),
                ctx=ctx,
            )
            return _json_text(result)

        elif name == "scan_local":
            result = await asyncio.to_thread(
                _run_local_scan,
                scan_path=arguments["scan_path"],
                regex_file=arguments.get("regex_file"),
                report_format=arguments.get("report_format", "n0s1"),
                show_matched_secret_on_logs=arguments.get("show_matched_secret_on_logs", False),
            )
            return _json_text(result)

        elif name == "get_scan_status":
            result = get_scan_status(arguments["report_uuid"], ctx=ctx)
            return _json_text(result)

        elif name == "get_scan_findings":
            severity_arg = arguments.get("severity")
            severity = Severity(severity_arg) if severity_arg else None
            result = get_scan_findings(
                arguments["report_uuid"],
                page=arguments.get("page"),
                severity=severity,
                ctx=ctx,
            )
            return _json_text(result)

        else:
            raise ValueError(f"Unknown tool: {name}")

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
