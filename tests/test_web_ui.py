"""Tests for the FORK web UI (access guard, tool toggles, persistence)."""
import json
from unittest.mock import MagicMock

from starlette.testclient import TestClient
from fastmcp import FastMCP

import src.web_ui as web_ui


def make_server(tmp_path, monkeypatch, peer_ok=True):
    monkeypatch.setenv("MCP_UI_SETTINGS", str(tmp_path / "ui.json"))
    monkeypatch.delenv("SUPERVISOR_TOKEN", raising=False)
    monkeypatch.setattr(web_ui, "in_addon", lambda: False)
    monkeypatch.setattr(web_ui, "_allowed", lambda request: peer_ok)
    mcp = FastMCP("t")

    @mcp.tool()
    def mealie_webhooks_list() -> str:
        """List webhooks."""
        return "x"

    @mcp.tool()
    def mealie_recipes_get() -> str:
        """Get a recipe."""
        return "y"

    web_ui.register_ui(mcp)
    return mcp, TestClient(mcp.http_app(path="/mcp"))


def test_index_and_tools(tmp_path, monkeypatch):
    mcp, c = make_server(tmp_path, monkeypatch)
    assert c.get("/").status_code == 200
    tools = c.get("/ui/api/tools").json()["tools"]
    assert {t["name"] for t in tools} == {"mealie_webhooks_list", "mealie_recipes_get"}
    assert {t["category"] for t in tools} == {"Automation", "Recipes"}


def test_toggle_persists_and_hides(tmp_path, monkeypatch):
    import asyncio
    mcp, c = make_server(tmp_path, monkeypatch)
    r = c.post("/ui/api/tools", json={"name": "mealie_webhooks_list", "enabled": False})
    assert r.json()["disabled"] == ["mealie_webhooks_list"]
    assert json.loads((tmp_path / "ui.json").read_text())["disabled_tools"] == ["mealie_webhooks_list"]
    names = [t.name for t in asyncio.run(mcp.list_tools())]
    assert names == ["mealie_recipes_get"]
    # still listed in the UI so it can be turned back on
    assert len(c.get("/ui/api/tools").json()["tools"]) == 2
    c.post("/ui/api/tools", json={"name": "mealie_webhooks_list", "enabled": True})
    assert len(asyncio.run(mcp.list_tools())) == 2


def test_saved_settings_applied_on_start(tmp_path, monkeypatch):
    import asyncio
    (tmp_path / "ui.json").write_text(json.dumps({"disabled_tools": ["mealie_recipes_get", "gone_tool"]}))
    mcp, c = make_server(tmp_path, monkeypatch)
    assert [t.name for t in asyncio.run(mcp.list_tools())] == ["mealie_webhooks_list"]


def test_unknown_tool_rejected(tmp_path, monkeypatch):
    _, c = make_server(tmp_path, monkeypatch)
    assert c.post("/ui/api/tools", json={"name": "nope", "enabled": False}).status_code == 400


def test_guard_blocks(tmp_path, monkeypatch):
    _, c = make_server(tmp_path, monkeypatch, peer_ok=False)
    assert c.get("/ui/api/status").status_code == 403


def test_allowed_rules(monkeypatch):
    req = MagicMock()
    req.client.host = "172.30.32.2"
    monkeypatch.setattr(web_ui, "in_addon", lambda: True)
    assert web_ui._allowed(req)
    req.client.host = "192.168.1.20"
    assert not web_ui._allowed(req)
    monkeypatch.setattr(web_ui, "in_addon", lambda: False)
    req.client.host = "127.0.0.1"
    assert web_ui._allowed(req)
    req.client.host = "192.168.1.20"
    assert not web_ui._allowed(req)
    monkeypatch.setenv("MCP_UI_ALLOW_REMOTE", "1")
    assert web_ui._allowed(req)
