# Changelog

## [1.1.0] — 2026-05-05 (Phase A1.2)

### Changed

- **Refactored onto `n0s1.mcp_tools`** (Phase A1.2 of the agent-native roadmap).
  Tool logic is now implemented in the transport-agnostic `n0s1.mcp_tools` submodule
  of the `n0s1` package. The stdio server acts as a thin adapter that translates
  MCP arguments into shared-spec function calls and serialises Pydantic responses as JSON.

- **Structured JSON responses.** All tools now return a JSON object (serialised
  `ScanResult`, `Status`, or `FindingsPage`) instead of a plain-text summary. The
  structure is consistent across stdio and the future HTTP+SSE transport.

- **`scan_local` kept locally.** Not part of the shared spec; implemented directly
  in the stdio server. Behaviour and arguments are unchanged.

- **Backwards-compatible MCP argument names preserved.** All existing required and
  optional argument names (`server`, `email`, `api_key`, `owner`, `scope`, `branch`,
  `report_format`, `show_matched_secret_on_logs`) are unchanged. No edits required
  to existing Claude Desktop / Cursor / IDE configurations.

- **Env-var credential fallback preserved.** `JIRA_TOKEN`, `JIRA_EMAIL`,
  `SLACK_TOKEN`, `GITHUB_TOKEN`, `GITLAB_TOKEN`, `ZENDESK_TOKEN`, `ZENDESK_EMAIL`,
  `LINEAR_TOKEN`, `ASANA_TOKEN`, `WRIKE_TOKEN` continue to work as before.

- **`RUNNER_ENV` env var honoured** by the new `stdio_context()` factory (defaults
  to `"DOCKER"`).

### Added

- **`get_scan_status` tool.** Returns `{report_uuid, status, progress_pct, error}`
  for a previously started scan.

- **`get_scan_findings` tool.** Returns a paginated list of redacted findings for a
  completed scan. Supports `page` (cursor) and `severity` filter arguments.

- **`report_format` and `show_matched_secret_on_logs`** are now accepted by all
  `scan_*` tools (including those that previously ignored them) and passed through
  to the underlying scanner.

## [1.0.4] — prior release

See git history.
