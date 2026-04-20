import asyncio
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import n0s1_mcp_server as server


def test_target_map_complete():
    expected = {"jira_scan", "confluence_scan", "slack_scan", "github_scan", "gitlab_scan",
                "zendesk_scan", "linear_scan", "asana_scan", "wrike_scan", "local_scan"}
    assert set(server._TARGET_MAP.values()) == expected


def test_env_map_covers_all_api_platforms():
    api_targets = set(server._TARGET_MAP.values()) - {"local_scan"}
    assert api_targets == set(server._ENV_MAP.keys())


def test_list_tools_returns_all_platforms():
    tools = asyncio.run(server.list_tools())
    names = {t.name for t in tools}
    assert names == set(server._TARGET_MAP.keys())


def test_each_tool_has_required_fields():
    tools = asyncio.run(server.list_tools())
    for tool in tools:
        assert tool.name
        assert tool.description
        assert "properties" in tool.inputSchema
        assert "required" in tool.inputSchema


def test_call_tool_unknown_name():
    result = asyncio.run(server.call_tool("scan_unknown", {}))
    assert len(result) == 1
    assert "Error" in result[0].text


def test_call_tool_env_fallback(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token-123")

    captured = {}

    def fake_run_scan(target, **kwargs):
        captured.update({"target": target, "kwargs": kwargs})
        return "mocked"

    monkeypatch.setattr(server, "run_scan", fake_run_scan)

    asyncio.run(server.call_tool("scan_github", {"owner": "myorg"}))
    assert captured["kwargs"].get("api_key") == "test-token-123"
