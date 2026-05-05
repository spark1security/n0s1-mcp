"""Tests for n0s1_mcp_server — Phase A1.2 refactor."""
import asyncio
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import n0s1_mcp_server as server

from n0s1.mcp_tools import (
    Finding,
    FindingsPage,
    ScanResult,
    ScanSummary,
    Severity,
    Status,
    Usage,
)

# ─── Helpers ─────────────────────────────────────────────────────────────────

_SHARED_SPEC_TOOLS = {
    "scan_jira", "scan_confluence", "scan_slack", "scan_asana", "scan_linear",
    "scan_zendesk", "scan_wrike", "scan_github", "scan_gitlab",
    "get_scan_status", "get_scan_findings",
}
_LOCAL_TOOLS = {"scan_local"}
_ALL_TOOLS = _SHARED_SPEC_TOOLS | _LOCAL_TOOLS


def _fake_scan_result(report_uuid="test-uuid"):
    return ScanResult(
        report_uuid=report_uuid,
        status="complete",
        summary=ScanSummary(
            total_findings=1,
            by_severity={Severity.high: 1},
            by_type={"aws-access-token": 1},
        ),
        findings=[
            Finding(
                file="https://jira.example.com/browse/SEC-1",
                line=None,
                type="aws-access-token",
                severity=Severity.high,
                redacted_match="AKIA****MPLE",
            )
        ],
        usage=Usage(
            tokens_in_estimate=100,
            tokens_out_actual=50,
            tokens_saved_estimate=50,
            savings_pct=50.0,
        ),
    )


# ─── Registration tests ───────────────────────────────────────────────────────

def test_list_tools_returns_all_expected_names():
    tools = asyncio.run(server.list_tools())
    names = {t.name for t in tools}
    assert names == _ALL_TOOLS


def test_shared_spec_tools_all_registered():
    tools = asyncio.run(server.list_tools())
    names = {t.name for t in tools}
    assert _SHARED_SPEC_TOOLS.issubset(names)


def test_scan_local_registered():
    tools = asyncio.run(server.list_tools())
    names = {t.name for t in tools}
    assert "scan_local" in names


def test_each_tool_has_required_fields():
    tools = asyncio.run(server.list_tools())
    for tool in tools:
        assert tool.name
        assert tool.description
        assert "properties" in tool.inputSchema
        assert "required" in tool.inputSchema


# ─── Backwards-compatible argument names ─────────────────────────────────────

def test_scan_jira_required_args():
    tools = asyncio.run(server.list_tools())
    jira = next(t for t in tools if t.name == "scan_jira")
    assert set(jira.inputSchema["required"]) == {"server", "email", "api_key"}


def test_scan_github_required_args():
    tools = asyncio.run(server.list_tools())
    gh = next(t for t in tools if t.name == "scan_github")
    assert set(gh.inputSchema["required"]) == {"api_key", "owner"}


def test_scan_slack_required_args():
    tools = asyncio.run(server.list_tools())
    sl = next(t for t in tools if t.name == "scan_slack")
    assert set(sl.inputSchema["required"]) == {"api_key"}


def test_scan_local_required_args():
    tools = asyncio.run(server.list_tools())
    loc = next(t for t in tools if t.name == "scan_local")
    assert set(loc.inputSchema["required"]) == {"scan_path"}


# ─── Passthrough args present in schemas ─────────────────────────────────────

@pytest.mark.parametrize("tool_name", list(_SHARED_SPEC_TOOLS - {"get_scan_status", "get_scan_findings"}) + ["scan_local"])
def test_report_format_and_show_secret_present(tool_name):
    tools = asyncio.run(server.list_tools())
    tool = next(t for t in tools if t.name == tool_name)
    props = tool.inputSchema["properties"]
    assert "report_format" in props
    assert "show_matched_secret_on_logs" in props


# ─── Round-trip tests ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("tool_name,args", [
    ("scan_jira",       {"server": "https://x.atlassian.net", "email": "u@x.com", "api_key": "tok"}),
    ("scan_confluence", {"server": "https://x.atlassian.net", "email": "u@x.com", "api_key": "tok"}),
    ("scan_slack",      {"api_key": "xoxb-fake"}),
    ("scan_asana",      {"api_key": "fake"}),
    ("scan_linear",     {"api_key": "lin_api_fake"}),
    ("scan_zendesk",    {"server": "x.zendesk.com", "email": "u@x.com", "api_key": "tok"}),
    ("scan_wrike",      {"api_key": "fake"}),
    ("scan_github",     {"api_key": "ghp_fake", "owner": "spark1security"}),
    ("scan_gitlab",     {"api_key": "glpat_fake", "owner": "mygroup"}),
])
def test_call_tool_returns_valid_json_scan_result(tool_name, args, monkeypatch):
    fake = _fake_scan_result()

    # Patch the shared-spec function imported in server module.
    fn_name = tool_name  # e.g. "scan_jira"
    monkeypatch.setattr(server, fn_name, lambda *a, **kw: fake)

    results = asyncio.run(server.call_tool(tool_name, args))
    assert len(results) == 1
    payload = json.loads(results[0].text)
    # Must validate against ScanResult schema
    parsed = ScanResult.model_validate(payload)
    assert parsed.status == "complete"
    assert parsed.summary.total_findings == 1


def test_call_tool_scan_local_returns_valid_json(monkeypatch):
    fake = _fake_scan_result()
    monkeypatch.setattr(server, "_run_local_scan", lambda *a, **kw: fake)
    results = asyncio.run(server.call_tool("scan_local", {"scan_path": "/tmp/test"}))
    assert len(results) == 1
    payload = json.loads(results[0].text)
    parsed = ScanResult.model_validate(payload)
    assert parsed.status == "complete"


def test_call_tool_get_scan_status(monkeypatch):
    fake_status = Status(report_uuid="abc", status="complete", progress_pct=100.0)
    monkeypatch.setattr(server, "get_scan_status", lambda *a, **kw: fake_status)
    results = asyncio.run(server.call_tool("get_scan_status", {"report_uuid": "abc"}))
    payload = json.loads(results[0].text)
    parsed = Status.model_validate(payload)
    assert parsed.status == "complete"


def test_call_tool_get_scan_findings(monkeypatch):
    fake_page = FindingsPage(
        report_uuid="abc",
        findings=[],
        total=0,
        usage=Usage(tokens_in_estimate=10, tokens_out_actual=5, tokens_saved_estimate=5, savings_pct=50.0),
    )
    monkeypatch.setattr(server, "get_scan_findings", lambda *a, **kw: fake_page)
    results = asyncio.run(server.call_tool("get_scan_findings", {"report_uuid": "abc"}))
    payload = json.loads(results[0].text)
    FindingsPage.model_validate(payload)


# ─── Error handling ───────────────────────────────────────────────────────────

def test_call_tool_unknown_name():
    results = asyncio.run(server.call_tool("scan_unknown", {}))
    assert len(results) == 1
    assert "Error" in results[0].text


def test_call_tool_missing_required_arg():
    # scan_jira without 'server' should produce an error (KeyError)
    results = asyncio.run(server.call_tool("scan_jira", {"email": "u@x.com", "api_key": "tok"}))
    assert len(results) == 1
    assert "Error" in results[0].text


# ─── Env-var fallback ─────────────────────────────────────────────────────────

def test_github_env_fallback_reaches_shared_spec(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "env-token-999")
    captured = {}

    def fake_scan_github(*a, **kw):
        captured.update(kw)
        return _fake_scan_result()

    monkeypatch.setattr(server, "scan_github", fake_scan_github)
    asyncio.run(server.call_tool("scan_github", {"owner": "myorg"}))
    assert captured.get("api_key") == "env-token-999"


def test_jira_env_fallback_reaches_shared_spec(monkeypatch):
    monkeypatch.setenv("JIRA_TOKEN", "jira-env-tok")
    monkeypatch.setenv("JIRA_EMAIL", "env@example.com")
    captured = {}

    def fake_scan_jira(*a, **kw):
        captured.update(kw)
        return _fake_scan_result()

    monkeypatch.setattr(server, "scan_jira", fake_scan_jira)
    asyncio.run(server.call_tool("scan_jira", {"server": "https://x.atlassian.net"}))
    assert captured.get("api_key") == "jira-env-tok"
    assert captured.get("email") == "env@example.com"


# ─── stdio_context ───────────────────────────────────────────────────────────

def test_stdio_context_defaults():
    ctx = server.stdio_context()
    assert ctx.user_id is None
    assert ctx.token_id is None
    assert ctx.on_scan_event is None
    assert ctx.runner == "DOCKER"


def test_stdio_context_runner_env_override(monkeypatch):
    monkeypatch.setenv("RUNNER_ENV", "AWS")
    ctx = server.stdio_context()
    assert ctx.runner == "AWS"


# ─── server.json manifest consistency ────────────────────────────────────────

def test_server_json_version_matches_pyproject():
    import tomllib
    import pathlib
    root = pathlib.Path(__file__).parent.parent
    with open(root / "pyproject.toml", "rb") as f:
        pyproject = tomllib.load(f)
    with open(root / "server.json") as f:
        manifest = json.load(f)
    assert manifest["version"] == pyproject["project"]["version"]
