import asyncio
import json
import os
import uuid

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, TextContent, Tool, ToolAnnotations

from n0s1.mcp_tools import (
    AnalysisStatus,
    Finding,
    FindingsPage,
    ScanResult,
    ScanSummary,
    Severity,
    Status,
    ToolContext,
    Usage,
    analyze_report,
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
    report_uuid: str | None = None,
) -> ScanResult:
    report_uuid = report_uuid or str(uuid.uuid4())
    kwargs: dict = {
        "scan_path": scan_path,
        "show_matched_secret_on_logs": show_matched_secret_on_logs,
        "post_comment": False,
        "report_format": report_format,
    }
    if regex_file:
        kwargs["regex_file"] = regex_file
    if report_uuid:
        kwargs["report_uuid"] = report_uuid

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
        use = usage_block(s.raw_chars_scanned, report_json)
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

# ─── Output schemas (derived from Pydantic models) ───────────────────────────

_SCAN_SCHEMA     = ScanResult.model_json_schema()
_STATUS_SCHEMA   = Status.model_json_schema()
_FINDINGS_SCHEMA = FindingsPage.model_json_schema()
_ANALYSIS_SCHEMA = AnalysisStatus.model_json_schema()

# Shared annotations
# scan_* tools read from the target platform but write a report to the n0s1
# backend, so readOnlyHint=False; they never delete or modify source content.
_SCAN_ANN  = ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=True)
_READ_ANN  = ToolAnnotations(readOnlyHint=True,  openWorldHint=False)
_WRITE_ANN = ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=True)

# ─── Tool definitions ─────────────────────────────────────────────────────────

@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="scan_jira",
            description=(
                "Read Jira tickets and comments to detect leaked secrets (API keys, tokens, passwords). "
                "Never modifies Jira — no comments are posted, no tickets are changed. "
                "Auth: requires JIRA_TOKEN and JIRA_EMAIL env vars, or pass api_key/email directly. "
                "Side effects: a redacted scan report is uploaded to the n0s1 backend; "
                "set allow_secret_upload=True to also upload AES-encrypted secret values for AI validation. "
                "Returns redacted findings — raw secret values are never included in the output. "
                "Subject to Jira API rate limits."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "server":        {"type": "string", "description": "Jira server URL e.g. https://company.atlassian.net"},
                    "email":         {"type": "string", "description": "Jira user email (or set JIRA_EMAIL env var)"},
                    "api_key":       {"type": "string", "description": "Jira API token (or set JIRA_TOKEN env var)"},
                    "scope":         {"type": "string", "description": "JQL query e.g. jql:project = SEC"},
                    "report_format": {"type": "string", "enum": ["n0s1", "sarif", "gitlab"], "default": "n0s1", "description": "Output report format"},
                    "show_matched_secret_on_logs": {"type": "boolean", "description": "Include redacted secret snippets in logs (default: false)"},
                    "ai_analysis":   {"type": "boolean", "description": "Queue async AI credential validation after the scan (requires n0s1 Pro)"},
                    "n0s1_api_key":  {"type": "string", "description": "n0s1 API key; overrides the N0S1_TOKEN env var"},
                    "allow_secret_upload": {"type": "boolean", "description": "Upload AES-encrypted secret values to the n0s1 backend for AI validation (default: false)"},
                    "report_uuid": {"type": "string", "description": "UUID to assign to the scan report; overrides the auto-generated one"},
                },
                "required": ["server", "email", "api_key"],
            },
            outputSchema=_SCAN_SCHEMA,
            annotations=_SCAN_ANN,
        ),
        Tool(
            name="scan_confluence",
            description=(
                "Read Confluence pages and comments to detect leaked secrets (API keys, tokens, passwords). "
                "Never modifies Confluence — no pages or comments are written. "
                "Auth: requires CONFLUENCE_TOKEN (falls back to JIRA_TOKEN) and CONFLUENCE_EMAIL "
                "(falls back to JIRA_EMAIL) env vars, or pass api_key/email directly. "
                "Side effects: a redacted scan report is uploaded to the n0s1 backend; "
                "set allow_secret_upload=True to also upload AES-encrypted secret values for AI validation. "
                "Returns redacted findings — raw secret values are never included in the output. "
                "Subject to Confluence API rate limits."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "server":        {"type": "string", "description": "Confluence server URL e.g. https://company.atlassian.net"},
                    "email":         {"type": "string", "description": "Confluence user email (or set CONFLUENCE_EMAIL / JIRA_EMAIL env var)"},
                    "api_key":       {"type": "string", "description": "Confluence API token (or set CONFLUENCE_TOKEN / JIRA_TOKEN env var)"},
                    "scope":         {"type": "string", "description": "CQL query e.g. cql:space=SEC and type=page"},
                    "report_format": {"type": "string", "enum": ["n0s1", "sarif", "gitlab"], "default": "n0s1", "description": "Output report format"},
                    "show_matched_secret_on_logs": {"type": "boolean", "description": "Include redacted secret snippets in logs (default: false)"},
                    "ai_analysis":   {"type": "boolean", "description": "Queue async AI credential validation after the scan (requires n0s1 Pro)"},
                    "n0s1_api_key":  {"type": "string", "description": "n0s1 API key; overrides the N0S1_TOKEN env var"},
                    "allow_secret_upload": {"type": "boolean", "description": "Upload AES-encrypted secret values to the n0s1 backend for AI validation (default: false)"},
                    "report_uuid": {"type": "string", "description": "UUID to assign to the scan report; overrides the auto-generated one"},
                },
                "required": ["server", "email", "api_key"],
            },
            outputSchema=_SCAN_SCHEMA,
            annotations=_SCAN_ANN,
        ),
        Tool(
            name="scan_slack",
            description=(
                "Read Slack messages to detect leaked secrets (API keys, tokens, passwords). "
                "Never modifies Slack — no messages are posted or edited. "
                "Auth: requires a bot token with channels:history and channels:read scopes; "
                "set SLACK_TOKEN env var or pass api_key directly. "
                "Side effects: a redacted scan report is uploaded to the n0s1 backend; "
                "set allow_secret_upload=True to also upload AES-encrypted secret values for AI validation. "
                "Returns redacted findings — raw secret values are never included in the output. "
                "Subject to Slack API rate limits."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key":       {"type": "string", "description": "Slack bot token with channels:history and channels:read scopes (or set SLACK_TOKEN env var)"},
                    "report_format": {"type": "string", "enum": ["n0s1", "sarif", "gitlab"], "default": "n0s1", "description": "Output report format"},
                    "show_matched_secret_on_logs": {"type": "boolean", "description": "Include redacted secret snippets in logs (default: false)"},
                    "ai_analysis":   {"type": "boolean", "description": "Queue async AI credential validation after the scan (requires n0s1 Pro)"},
                    "n0s1_api_key":  {"type": "string", "description": "n0s1 API key; overrides the N0S1_TOKEN env var"},
                    "allow_secret_upload": {"type": "boolean", "description": "Upload AES-encrypted secret values to the n0s1 backend for AI validation (default: false)"},
                    "report_uuid": {"type": "string", "description": "UUID to assign to the scan report; overrides the auto-generated one"},
                },
                "required": ["api_key"],
            },
            outputSchema=_SCAN_SCHEMA,
            annotations=_SCAN_ANN,
        ),
        Tool(
            name="scan_github",
            description=(
                "Read GitHub repository code, issues, and pull requests to detect leaked secrets. "
                "Never modifies GitHub — no commits, comments, or PRs are created. "
                "Auth: requires a personal access token with repo (or public_repo) scope; "
                "set GITHUB_TOKEN env var or pass api_key directly. "
                "Side effects: a redacted scan report is uploaded to the n0s1 backend; "
                "set allow_secret_upload=True to also upload AES-encrypted secret values for AI validation. "
                "Returns redacted findings — raw secret values are never included in the output. "
                "Subject to GitHub API rate limits (5,000 req/hr authenticated)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key": {"type": "string", "description": "GitHub personal access token with repo scope (or set GITHUB_TOKEN env var)"},
                    "owner":   {"type": "string", "description": "GitHub org or user name"},
                    "repo":    {"type": "string", "description": "Repository name (optional — omit to scan all repos for owner)"},
                    "branch":  {"type": "string", "description": "Branch to scan (optional — defaults to default branch)"},
                    "scope":   {"type": "string", "description": "Search query e.g. search:org:myorg"},
                    "report_format": {"type": "string", "enum": ["n0s1", "sarif", "gitlab"], "default": "n0s1", "description": "Output report format"},
                    "show_matched_secret_on_logs": {"type": "boolean", "description": "Include redacted secret snippets in logs (default: false)"},
                    "ai_analysis":   {"type": "boolean", "description": "Queue async AI credential validation after the scan (requires n0s1 Pro)"},
                    "n0s1_api_key":  {"type": "string", "description": "n0s1 API key; overrides the N0S1_TOKEN env var"},
                    "allow_secret_upload": {"type": "boolean", "description": "Upload AES-encrypted secret values to the n0s1 backend for AI validation (default: false)"},
                    "report_uuid": {"type": "string", "description": "UUID to assign to the scan report; overrides the auto-generated one"},
                },
                "required": ["api_key", "owner"],
            },
            outputSchema=_SCAN_SCHEMA,
            annotations=_SCAN_ANN,
        ),
        Tool(
            name="scan_gitlab",
            description=(
                "Read GitLab project code, issues, and merge requests to detect leaked secrets. "
                "Never modifies GitLab — no commits, comments, or MRs are created. "
                "Auth: requires a personal access token with read_api scope; "
                "set GITLAB_TOKEN env var or pass api_key directly. "
                "Side effects: a redacted scan report is uploaded to the n0s1 backend; "
                "set allow_secret_upload=True to also upload AES-encrypted secret values for AI validation. "
                "Returns redacted findings — raw secret values are never included in the output. "
                "Subject to GitLab API rate limits."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key": {"type": "string", "description": "GitLab personal access token with read_api scope (or set GITLAB_TOKEN env var)"},
                    "server":  {"type": "string", "description": "GitLab server URL (default: https://gitlab.com or GITLAB_URL env var)"},
                    "owner":   {"type": "string", "description": "GitLab group or user name"},
                    "repo":    {"type": "string", "description": "Project name (optional — omit to scan all projects for owner)"},
                    "branch":  {"type": "string", "description": "Branch to scan (optional — defaults to default branch)"},
                    "report_format": {"type": "string", "enum": ["n0s1", "sarif", "gitlab"], "default": "n0s1", "description": "Output report format"},
                    "show_matched_secret_on_logs": {"type": "boolean", "description": "Include redacted secret snippets in logs (default: false)"},
                    "ai_analysis":   {"type": "boolean", "description": "Queue async AI credential validation after the scan (requires n0s1 Pro)"},
                    "n0s1_api_key":  {"type": "string", "description": "n0s1 API key; overrides the N0S1_TOKEN env var"},
                    "allow_secret_upload": {"type": "boolean", "description": "Upload AES-encrypted secret values to the n0s1 backend for AI validation (default: false)"},
                    "report_uuid": {"type": "string", "description": "UUID to assign to the scan report; overrides the auto-generated one"},
                },
                "required": ["api_key", "owner"],
            },
            outputSchema=_SCAN_SCHEMA,
            annotations=_SCAN_ANN,
        ),
        Tool(
            name="scan_zendesk",
            description=(
                "Read Zendesk tickets and comments to detect leaked secrets (API keys, tokens, passwords). "
                "Never modifies Zendesk — no tickets or comments are written. "
                "Auth: requires ZENDESK_TOKEN, ZENDESK_EMAIL, and ZENDESK_SERVER env vars, "
                "or pass server/email/api_key directly. "
                "Side effects: a redacted scan report is uploaded to the n0s1 backend; "
                "set allow_secret_upload=True to also upload AES-encrypted secret values for AI validation. "
                "Returns redacted findings — raw secret values are never included in the output. "
                "Subject to Zendesk API rate limits."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "server":  {"type": "string", "description": "Zendesk subdomain e.g. mycompany.zendesk.com (or set ZENDESK_SERVER env var)"},
                    "email":   {"type": "string", "description": "Zendesk agent email (or set ZENDESK_EMAIL env var)"},
                    "api_key": {"type": "string", "description": "Zendesk API token (or set ZENDESK_TOKEN env var)"},
                    "report_format": {"type": "string", "enum": ["n0s1", "sarif", "gitlab"], "default": "n0s1", "description": "Output report format"},
                    "show_matched_secret_on_logs": {"type": "boolean", "description": "Include redacted secret snippets in logs (default: false)"},
                    "ai_analysis":   {"type": "boolean", "description": "Queue async AI credential validation after the scan (requires n0s1 Pro)"},
                    "n0s1_api_key":  {"type": "string", "description": "n0s1 API key; overrides the N0S1_TOKEN env var"},
                    "allow_secret_upload": {"type": "boolean", "description": "Upload AES-encrypted secret values to the n0s1 backend for AI validation (default: false)"},
                    "report_uuid": {"type": "string", "description": "UUID to assign to the scan report; overrides the auto-generated one"},
                },
                "required": ["server", "email", "api_key"],
            },
            outputSchema=_SCAN_SCHEMA,
            annotations=_SCAN_ANN,
        ),
        Tool(
            name="scan_linear",
            description=(
                "Read Linear issues and comments to detect leaked secrets (API keys, tokens, passwords). "
                "Never modifies Linear — no issues or comments are written. "
                "Auth: requires a Linear personal API key (lin_api_...); "
                "set LINEAR_TOKEN env var or pass api_key directly. "
                "Side effects: a redacted scan report is uploaded to the n0s1 backend; "
                "set allow_secret_upload=True to also upload AES-encrypted secret values for AI validation. "
                "Returns redacted findings — raw secret values are never included in the output. "
                "Subject to Linear API rate limits."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key": {"type": "string", "description": "Linear personal API key (lin_api_...) (or set LINEAR_TOKEN env var)"},
                    "report_format": {"type": "string", "enum": ["n0s1", "sarif", "gitlab"], "default": "n0s1", "description": "Output report format"},
                    "show_matched_secret_on_logs": {"type": "boolean", "description": "Include redacted secret snippets in logs (default: false)"},
                    "ai_analysis":   {"type": "boolean", "description": "Queue async AI credential validation after the scan (requires n0s1 Pro)"},
                    "n0s1_api_key":  {"type": "string", "description": "n0s1 API key; overrides the N0S1_TOKEN env var"},
                    "allow_secret_upload": {"type": "boolean", "description": "Upload AES-encrypted secret values to the n0s1 backend for AI validation (default: false)"},
                    "report_uuid": {"type": "string", "description": "UUID to assign to the scan report; overrides the auto-generated one"},
                },
                "required": ["api_key"],
            },
            outputSchema=_SCAN_SCHEMA,
            annotations=_SCAN_ANN,
        ),
        Tool(
            name="scan_asana",
            description=(
                "Read Asana tasks and comments to detect leaked secrets (API keys, tokens, passwords). "
                "Never modifies Asana — no tasks or comments are written. "
                "Auth: requires an Asana personal access token; "
                "set ASANA_TOKEN env var or pass api_key directly. "
                "Side effects: a redacted scan report is uploaded to the n0s1 backend; "
                "set allow_secret_upload=True to also upload AES-encrypted secret values for AI validation. "
                "Returns redacted findings — raw secret values are never included in the output. "
                "Subject to Asana API rate limits."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key": {"type": "string", "description": "Asana personal access token (or set ASANA_TOKEN env var)"},
                    "scope":   {"type": "string", "description": "Workspace or project scope filter"},
                    "report_format": {"type": "string", "enum": ["n0s1", "sarif", "gitlab"], "default": "n0s1", "description": "Output report format"},
                    "show_matched_secret_on_logs": {"type": "boolean", "description": "Include redacted secret snippets in logs (default: false)"},
                    "ai_analysis":   {"type": "boolean", "description": "Queue async AI credential validation after the scan (requires n0s1 Pro)"},
                    "n0s1_api_key":  {"type": "string", "description": "n0s1 API key; overrides the N0S1_TOKEN env var"},
                    "allow_secret_upload": {"type": "boolean", "description": "Upload AES-encrypted secret values to the n0s1 backend for AI validation (default: false)"},
                    "report_uuid": {"type": "string", "description": "UUID to assign to the scan report; overrides the auto-generated one"},
                },
                "required": ["api_key"],
            },
            outputSchema=_SCAN_SCHEMA,
            annotations=_SCAN_ANN,
        ),
        Tool(
            name="scan_wrike",
            description=(
                "Read Wrike tasks and comments to detect leaked secrets (API keys, tokens, passwords). "
                "Never modifies Wrike — no tasks or comments are written. "
                "Auth: requires a Wrike permanent access token; "
                "set WRIKE_TOKEN env var or pass api_key directly. "
                "Side effects: a redacted scan report is uploaded to the n0s1 backend; "
                "set allow_secret_upload=True to also upload AES-encrypted secret values for AI validation. "
                "Returns redacted findings — raw secret values are never included in the output. "
                "Subject to Wrike API rate limits."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key": {"type": "string", "description": "Wrike permanent access token (or set WRIKE_TOKEN env var)"},
                    "scope":   {"type": "string", "description": "Folder or space scope filter"},
                    "report_format": {"type": "string", "enum": ["n0s1", "sarif", "gitlab"], "default": "n0s1", "description": "Output report format"},
                    "show_matched_secret_on_logs": {"type": "boolean", "description": "Include redacted secret snippets in logs (default: false)"},
                    "ai_analysis":   {"type": "boolean", "description": "Queue async AI credential validation after the scan (requires n0s1 Pro)"},
                    "n0s1_api_key":  {"type": "string", "description": "n0s1 API key; overrides the N0S1_TOKEN env var"},
                    "allow_secret_upload": {"type": "boolean", "description": "Upload AES-encrypted secret values to the n0s1 backend for AI validation (default: false)"},
                    "report_uuid": {"type": "string", "description": "UUID to assign to the scan report; overrides the auto-generated one"},
                },
                "required": ["api_key"],
            },
            outputSchema=_SCAN_SCHEMA,
            annotations=_SCAN_ANN,
        ),
        Tool(
            name="scan_local",
            description=(
                "Scan a local filesystem path for leaked secrets (API keys, tokens, passwords). "
                "Fully local — no network calls, no data sent to any external service. "
                "Never modifies scanned files. No authentication required. "
                "Returns redacted findings — raw secret values are never included in the output."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_path":     {"type": "string", "description": "Absolute or relative path to scan"},
                    "regex_file":    {"type": "string", "description": "Path to custom regex YAML file (optional)"},
                    "report_format": {"type": "string", "enum": ["n0s1", "sarif", "gitlab"], "default": "n0s1", "description": "Output report format"},
                    "show_matched_secret_on_logs": {"type": "boolean", "description": "Include redacted secret snippets in logs (default: false)"},
                    "report_uuid": {"type": "string", "description": "UUID to assign to the scan report; overrides the auto-generated one"},
                },
                "required": ["scan_path"],
            },
            outputSchema=_SCAN_SCHEMA,
            annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
        ),
        Tool(
            name="get_scan_status",
            description=(
                "Return the current status of a previously started scan. "
                "Read-only with no side effects — queries in-process scan state only. "
                "Returns 'pending' if the report_uuid is not yet known."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "report_uuid": {"type": "string", "description": "UUID returned by the originating scan_* call"},
                },
                "required": ["report_uuid"],
            },
            outputSchema=_STATUS_SCHEMA,
            annotations=_READ_ANN,
        ),
        Tool(
            name="get_scan_findings",
            description=(
                "Return a paginated list of findings for a completed scan. "
                "Read-only with no side effects. "
                "All secret values are redacted — raw secrets are never returned. "
                "Pass next_cursor from a previous response to retrieve subsequent pages."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "report_uuid": {"type": "string", "description": "UUID returned by the originating scan_* call"},
                    "page":     {"type": "string", "description": "Opaque cursor from a previous response (omit for first page)"},
                    "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"], "description": "Filter findings to this severity level"},
                },
                "required": ["report_uuid"],
            },
            outputSchema=_FINDINGS_SCHEMA,
            annotations=_READ_ANN,
        ),
        Tool(
            name="analyze_report",
            description=(
                "Submit or advance async AI credential validation for a previously uploaded scan report. "
                "Side effects: sends live HTTP validation requests to check whether discovered credentials "
                "are still active — this contacts the services where the secrets were found. "
                "Auth: requires n0s1_api_key or N0S1_TOKEN env var (n0s1 Professional account). "
                "Call once to queue, then poll until ai_analysis_status is 'complete' or 'failed'. "
                "Pass report_file when status is 'waiting_client' to inject credentials into validators. "
                "Pass wait_minutes to block until a terminal state or timeout; "
                "returns ai_analysis_status='timeout' if the deadline is reached without completion."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "report_uuid":  {"type": "string", "description": "UUID returned by a scan_* tool or a previous analyze_report call"},
                    "n0s1_api_key": {"type": "string", "description": "n0s1 API key (or set N0S1_TOKEN env var) — required for AI analysis"},
                    "report_file":  {"type": "string", "description": "Path to local report JSON file — required when status is 'waiting_client'"},
                    "wait_minutes": {"type": "integer", "description": "Poll the backend every 30 s until a terminal state or this many minutes elapse. Returns ai_analysis_status='timeout' if the deadline is reached."},
                },
                "required": ["report_uuid"],
            },
            outputSchema=_ANALYSIS_SCHEMA,
            annotations=_WRITE_ANN,
        ),
    ]

# ─── Tool handlers ────────────────────────────────────────────────────────────

def _make_result(model) -> CallToolResult:
    payload = model.model_dump(mode="json")
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload))],
        structuredContent=payload,
    )


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> CallToolResult:
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
                ai_analysis=arguments.get("ai_analysis", False),
                n0s1_token=arguments.get("n0s1_api_key") or os.getenv("N0S1_TOKEN"),
                allow_secret_upload=arguments.get("allow_secret_upload", False),
                report_uuid=arguments.get("report_uuid"),
                ctx=ctx,
            )
            return _make_result(result)

        elif name == "scan_confluence":
            result = await asyncio.to_thread(
                scan_confluence,
                workspace_url=arguments["server"],
                scope=arguments.get("scope"),
                api_key=arguments.get("api_key") or os.getenv("JIRA_TOKEN"),
                email=arguments.get("email") or os.getenv("JIRA_EMAIL"),
                report_format=arguments.get("report_format", "n0s1"),
                show_matched_secret_on_logs=arguments.get("show_matched_secret_on_logs", False),
                ai_analysis=arguments.get("ai_analysis", False),
                n0s1_token=arguments.get("n0s1_api_key") or os.getenv("N0S1_TOKEN"),
                allow_secret_upload=arguments.get("allow_secret_upload", False),
                report_uuid=arguments.get("report_uuid"),
                ctx=ctx,
            )
            return _make_result(result)

        elif name == "scan_slack":
            result = await asyncio.to_thread(
                scan_slack,
                api_key=arguments.get("api_key") or os.getenv("SLACK_TOKEN"),
                report_format=arguments.get("report_format", "n0s1"),
                show_matched_secret_on_logs=arguments.get("show_matched_secret_on_logs", False),
                ai_analysis=arguments.get("ai_analysis", False),
                n0s1_token=arguments.get("n0s1_api_key") or os.getenv("N0S1_TOKEN"),
                allow_secret_upload=arguments.get("allow_secret_upload", False),
                report_uuid=arguments.get("report_uuid"),
                ctx=ctx,
            )
            return _make_result(result)

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
                ai_analysis=arguments.get("ai_analysis", False),
                n0s1_token=arguments.get("n0s1_api_key") or os.getenv("N0S1_TOKEN"),
                allow_secret_upload=arguments.get("allow_secret_upload", False),
                report_uuid=arguments.get("report_uuid"),
                ctx=ctx,
            )
            return _make_result(result)

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
                ai_analysis=arguments.get("ai_analysis", False),
                n0s1_token=arguments.get("n0s1_api_key") or os.getenv("N0S1_TOKEN"),
                allow_secret_upload=arguments.get("allow_secret_upload", False),
                report_uuid=arguments.get("report_uuid"),
                ctx=ctx,
            )
            return _make_result(result)

        elif name == "scan_zendesk":
            result = await asyncio.to_thread(
                scan_zendesk,
                workspace_url=arguments["server"],
                api_key=arguments.get("api_key") or os.getenv("ZENDESK_TOKEN"),
                email=arguments.get("email") or os.getenv("ZENDESK_EMAIL"),
                report_format=arguments.get("report_format", "n0s1"),
                show_matched_secret_on_logs=arguments.get("show_matched_secret_on_logs", False),
                ai_analysis=arguments.get("ai_analysis", False),
                n0s1_token=arguments.get("n0s1_api_key") or os.getenv("N0S1_TOKEN"),
                allow_secret_upload=arguments.get("allow_secret_upload", False),
                report_uuid=arguments.get("report_uuid"),
                ctx=ctx,
            )
            return _make_result(result)

        elif name == "scan_linear":
            result = await asyncio.to_thread(
                scan_linear,
                api_key=arguments.get("api_key") or os.getenv("LINEAR_TOKEN"),
                report_format=arguments.get("report_format", "n0s1"),
                show_matched_secret_on_logs=arguments.get("show_matched_secret_on_logs", False),
                ai_analysis=arguments.get("ai_analysis", False),
                n0s1_token=arguments.get("n0s1_api_key") or os.getenv("N0S1_TOKEN"),
                allow_secret_upload=arguments.get("allow_secret_upload", False),
                report_uuid=arguments.get("report_uuid"),
                ctx=ctx,
            )
            return _make_result(result)

        elif name == "scan_asana":
            result = await asyncio.to_thread(
                scan_asana,
                scope=arguments.get("scope"),
                api_key=arguments.get("api_key") or os.getenv("ASANA_TOKEN"),
                report_format=arguments.get("report_format", "n0s1"),
                show_matched_secret_on_logs=arguments.get("show_matched_secret_on_logs", False),
                ai_analysis=arguments.get("ai_analysis", False),
                n0s1_token=arguments.get("n0s1_api_key") or os.getenv("N0S1_TOKEN"),
                allow_secret_upload=arguments.get("allow_secret_upload", False),
                report_uuid=arguments.get("report_uuid"),
                ctx=ctx,
            )
            return _make_result(result)

        elif name == "scan_wrike":
            result = await asyncio.to_thread(
                scan_wrike,
                scope=arguments.get("scope"),
                api_key=arguments.get("api_key") or os.getenv("WRIKE_TOKEN"),
                report_format=arguments.get("report_format", "n0s1"),
                show_matched_secret_on_logs=arguments.get("show_matched_secret_on_logs", False),
                ai_analysis=arguments.get("ai_analysis", False),
                n0s1_token=arguments.get("n0s1_api_key") or os.getenv("N0S1_TOKEN"),
                allow_secret_upload=arguments.get("allow_secret_upload", False),
                report_uuid=arguments.get("report_uuid"),
                ctx=ctx,
            )
            return _make_result(result)

        elif name == "scan_local":
            result = await asyncio.to_thread(
                _run_local_scan,
                scan_path=arguments["scan_path"],
                regex_file=arguments.get("regex_file"),
                report_format=arguments.get("report_format", "n0s1"),
                show_matched_secret_on_logs=arguments.get("show_matched_secret_on_logs", False),
                report_uuid=arguments.get("report_uuid"),
            )
            return _make_result(result)

        elif name == "get_scan_status":
            result = get_scan_status(arguments["report_uuid"], ctx=ctx)
            return _make_result(result)

        elif name == "get_scan_findings":
            severity_arg = arguments.get("severity")
            severity = Severity(severity_arg) if severity_arg else None
            result = get_scan_findings(
                arguments["report_uuid"],
                page=arguments.get("page"),
                severity=severity,
                ctx=ctx,
            )
            return _make_result(result)

        elif name == "analyze_report":
            wait_minutes = arguments.get("wait_minutes")
            result = await asyncio.to_thread(
                analyze_report,
                arguments["report_uuid"],
                n0s1_token=arguments.get("n0s1_api_key") or os.getenv("N0S1_TOKEN"),
                report_file=arguments.get("report_file"),
                wait_minutes=int(wait_minutes) if wait_minutes is not None else None,
                ctx=ctx,
            )
            return _make_result(result)

        else:
            raise ValueError(f"Unknown tool: {name}")

    except Exception as e:
        return CallToolResult(
            content=[TextContent(type="text", text=f"Error running {name}: {e}")],
            isError=True,
        )

# ─── Entry point ──────────────────────────────────────────────────────────────

async def _async_main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


def main():
    asyncio.run(_async_main())


if __name__ == "__main__":
    main()
