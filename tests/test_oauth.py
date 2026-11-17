"""FORK: tests for the OAuth sign-in provider (src/oauth.py)."""

import base64
import hashlib
import secrets
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastmcp import FastMCP
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from oauth import MealieOAuthProvider, config_problems, oauth_settings  # noqa: E402

BASE = "https://mcp.example"
CLAUDE_CB = "https://claude.ai/api/mcp/auth_callback"
INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}
ACCEPT = {"accept": "application/json, text/event-stream"}


@pytest.fixture
def env(monkeypatch, tmp_path):
    for k, v in {"MCP_OAUTH_ENABLED": "true", "MCP_PUBLIC_URL": BASE, "MCP_AUTH_TOKEN": "static",
                 "MCP_OAUTH_PASSWORD": "pw", "MCP_OAUTH_CLIENT_ID": "gem", "MCP_OAUTH_CLIENT_SECRET": "sec",
                 "MCP_OAUTH_STATE_FILE": str(tmp_path / "state.json")}.items():
        monkeypatch.setenv(k, v)


def _client():
    mcp = FastMCP("test")

    @mcp.tool
    def ping() -> str:
        return "pong"

    mcp.auth = MealieOAuthProvider()
    return TestClient(mcp.http_app(path="/mcp"), base_url=BASE, follow_redirects=False)


@pytest.fixture
def client(env):
    with _client() as c:
        yield c


def _pkce():
    v = secrets.token_urlsafe(40)
    return v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()


def _approve(c, client_id, redirect, challenge, password="pw"):
    r = c.get("/authorize", params=dict(response_type="code", client_id=client_id, redirect_uri=redirect,
                                       state="st", code_challenge=challenge, code_challenge_method="S256"))
    assert r.status_code == 302, r.text
    txn = parse_qs(urlparse(r.headers["location"]).query)["txn"][0]
    return c.post("/oauth/consent", data=dict(txn=txn, password=password, action="allow"))


def _code(resp):
    return parse_qs(urlparse(resp.headers["location"]).query)["code"][0]


def _mcp(c, token):
    return c.post("/mcp", json=INIT, headers={**ACCEPT, "authorization": f"Bearer {token}"}).status_code


def test_config_problems():
    cfg = {"public_url": "", "password": "", "client_id": "x", "client_secret": ""}
    assert len(config_problems(cfg)) == 3


def test_discovery_and_challenge(client):
    md = client.get("/.well-known/oauth-authorization-server").json()
    assert md["registration_endpoint"] == f"{BASE}/register"
    r = client.post("/mcp", json=INIT, headers=ACCEPT)
    assert r.status_code == 401 and "resource_metadata" in r.headers["www-authenticate"]


def test_static_bearer_still_works(client):
    assert _mcp(client, "static") == 200
    assert _mcp(client, "wrong") == 401


def test_dynamic_registration_flow(client):
    reg = client.post("/register", json={"client_name": "Claude", "redirect_uris": [CLAUDE_CB],
                                         "token_endpoint_auth_method": "none"}).json()
    v, ch = _pkce()
    assert _approve(client, reg["client_id"], CLAUDE_CB, ch, password="no").status_code == 401
    r = _approve(client, reg["client_id"], CLAUDE_CB, ch)
    assert r.status_code == 302 and "state=st" in r.headers["location"]
    tok = client.post("/token", data=dict(grant_type="authorization_code", code=_code(r), redirect_uri=CLAUDE_CB,
                                          code_verifier=v, client_id=reg["client_id"])).json()
    assert _mcp(client, tok["access_token"]) == 200
    # registered clients can't use other callbacks
    r = client.get("/authorize", params=dict(response_type="code", client_id=reg["client_id"],
                                            redirect_uri="https://evil.example/cb", code_challenge=ch))
    assert r.status_code == 400


def test_static_client_basic_and_post_auth(client):
    v, ch = _pkce()
    code = _code(_approve(client, "gem", "https://gemini.example/cb", ch))
    r = client.post("/token", auth=("gem", "sec"), data=dict(
        grant_type="authorization_code", code=code, redirect_uri="https://gemini.example/cb", code_verifier=v))
    assert r.status_code == 200, r.text
    tok = r.json()
    assert _mcp(client, tok["access_token"]) == 200
    bad = dict(grant_type="refresh_token", refresh_token=tok["refresh_token"], client_id="gem", client_secret="no")
    assert client.post("/token", data=bad).status_code == 401
    ok = client.post("/token", data={**bad, "client_secret": "sec"})
    assert ok.status_code == 200
    # refresh tokens rotate
    assert client.post("/token", data={**bad, "client_secret": "sec"}).status_code >= 400


def test_static_client_rejects_plain_http_redirect(client):
    _, ch = _pkce()
    r = client.get("/authorize", params=dict(response_type="code", client_id="gem",
                                            redirect_uri="http://evil.example/cb", code_challenge=ch))
    assert r.status_code == 400


def test_deny_redirects_with_error(client):
    _, ch = _pkce()
    r = client.get("/authorize", params=dict(response_type="code", client_id="gem", redirect_uri="https://g.example/cb",
                                            state="st", code_challenge=ch))
    txn = parse_qs(urlparse(r.headers["location"]).query)["txn"][0]
    r = client.post("/oauth/consent", data=dict(txn=txn, action="deny"))
    assert "error=access_denied" in r.headers["location"]


def test_tokens_survive_restart(env):
    with _client() as c:
        v, ch = _pkce()
        code = _code(_approve(c, "gem", "https://g.example/cb", ch))
        tok = c.post("/token", auth=("gem", "sec"), data=dict(grant_type="authorization_code", code=code,
                                                              redirect_uri="https://g.example/cb",
                                                              code_verifier=v)).json()
    with _client() as c:
        assert _mcp(c, tok["access_token"]) == 200


def test_settings_disabled_by_default(monkeypatch):
    monkeypatch.delenv("MCP_OAUTH_ENABLED", raising=False)
    assert oauth_settings()["enabled"] is False


@pytest.mark.parametrize("value", [BASE, BASE + "/", BASE + "/mcp", BASE + "/mcp/"])
def test_public_url_strips_endpoint_path(monkeypatch, value):
    monkeypatch.setenv("MCP_PUBLIC_URL", value)
    assert oauth_settings()["public_url"] == BASE


def test_public_url_with_mcp_path_still_discoverable(env, monkeypatch):
    monkeypatch.setenv("MCP_PUBLIC_URL", BASE + "/mcp")
    with _client() as c:
        prm = c.get("/.well-known/oauth-protected-resource/mcp").json()
        assert prm["resource"] == BASE + "/mcp"
        assert prm["authorization_servers"] == [BASE + "/"] or prm["authorization_servers"] == [BASE]
        assert c.get("/.well-known/oauth-authorization-server").status_code == 200


def test_metadata_at_endpoint_path_for_gemini(client):
    for path in ("/.well-known/oauth-authorization-server/mcp", "/mcp/.well-known/oauth-authorization-server"):
        r = client.get(path)
        assert r.status_code == 200, path
        md = r.json()
        assert md["issuer"] == BASE + "/mcp"
        assert md["authorization_endpoint"] == BASE + "/authorize"
        assert md["token_endpoint"] == BASE + "/token"
