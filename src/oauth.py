"""
FORK: OAuth 2.1 sign-in for the MCP endpoint, built on FastMCP's OAuthProvider.

FastMCP (and the MCP SDK underneath) serve the standard endpoints: discovery
metadata, /authorize, /token, /register (dynamic client registration) and
/revoke. This module supplies what they leave to the server:

- storage for clients and tokens (JSON file, tokens stored as SHA-256 hashes),
- an approval page: whoever connects a client must type MCP_OAUTH_PASSWORD
  (falls back to MCP_AUTH_TOKEN), so open registration doesn't open access,
- an optional pre-registered client (MCP_OAUTH_CLIENT_ID / _SECRET) for clients
  that only accept a fixed client ID + secret (e.g. Gemini custom connectors),
- the static MCP_AUTH_TOKEN, still accepted as a bearer token so existing
  clients (Claude Code, Gemini CLI, HA Assist, ...) keep working.

Environment variables:
    MCP_OAUTH_ENABLED        "true" turns OAuth on
    MCP_PUBLIC_URL           Required with OAuth: external base URL without /mcp,
                             e.g. https://mealie-mcp.example.com
    MCP_OAUTH_PASSWORD       Approval password (default: MCP_AUTH_TOKEN)
    MCP_OAUTH_CLIENT_ID      } optional pre-registered client
    MCP_OAUTH_CLIENT_SECRET  }
    MCP_OAUTH_REDIRECT_URIS  Comma-separated callback allowlist for the
                             pre-registered client. Empty = any https URI (plus
                             http://localhost). Registered clients always use
                             the callbacks they registered.
    MCP_OAUTH_STATE_FILE     Store path (default /data/oauth_state.json in the
                             Home Assistant app)
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import html
import json
import logging
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from fastmcp.server.auth.auth import AccessToken, OAuthProvider, TokenHandler
from mcp.server.auth.middleware.client_auth import AuthenticationError, ClientAuthenticator
from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.server.auth.routes import cors_middleware
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import InvalidRedirectUriError, OAuthClientInformationFull, OAuthToken
from pydantic import AnyUrl
from starlette.datastructures import FormData
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

log = logging.getLogger("mealie_mcp.oauth")

ACCESS_TTL = 3600
REFRESH_TTL = 90 * 24 * 3600
CODE_TTL = 300
CONSENT_TTL = 600
MAX_FAILS = 5
FAIL_WINDOW = 600
MAX_CLIENTS = 50
CONSENT_PATH = "/oauth/consent"
STATIC_BEARER_CLIENT = "static-bearer-token"
SCOPE = "mealie"


def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def oauth_settings() -> dict[str, Any]:
    """OAuth configuration from the environment (shared with run.py / web UI)."""
    return {
        "enabled": os.getenv("MCP_OAUTH_ENABLED", "").strip().lower() in ("1", "true", "yes", "on"),
        "public_url": os.getenv("MCP_PUBLIC_URL", "").strip().rstrip("/"),
        "password": (os.getenv("MCP_OAUTH_PASSWORD", "").strip()
                     or os.getenv("MCP_AUTH_TOKEN", "").strip()),
        "client_id": os.getenv("MCP_OAUTH_CLIENT_ID", "").strip(),
        "client_secret": os.getenv("MCP_OAUTH_CLIENT_SECRET", "").strip(),
        "redirect_uris": [u.strip() for u in os.getenv("MCP_OAUTH_REDIRECT_URIS", "").split(",") if u.strip()],
        "static_token": os.getenv("MCP_AUTH_TOKEN", "").strip(),
    }


def config_problems(cfg: dict[str, Any]) -> list[str]:
    """Reasons OAuth can't start. Empty list = OK."""
    out = []
    if not cfg["public_url"].startswith(("https://", "http://")):
        out.append("public_url must be set to this app's public HTTPS address (without /mcp).")
    if not cfg["password"]:
        out.append("set oauth_password (or mcp_auth_token) so connections can be approved.")
    if bool(cfg["client_id"]) != bool(cfg["client_secret"]):
        out.append("set both oauth_client_id and oauth_client_secret, or neither.")
    return out


# ----------------------------------------------------------------- clients
class _Client(OAuthClientInformationFull):
    """Scopes carry no meaning here, so any requested scope is accepted."""

    def validate_scope(self, requested_scope: str | None) -> list[str] | None:
        if requested_scope is None:
            return None
        return [s for s in requested_scope.split(" ") if s]


class _StaticClient(_Client):
    """Pre-registered client: callbacks checked against an allowlist or https."""

    def validate_redirect_uri(self, redirect_uri: AnyUrl | None) -> AnyUrl:
        allow = oauth_settings()["redirect_uris"]
        if redirect_uri is None:
            if len(allow) == 1:
                return AnyUrl(allow[0])
            raise InvalidRedirectUriError("redirect_uri is required")
        uri = str(redirect_uri)
        p = urlparse(uri)
        ok = (uri in allow) if allow else (
            not p.fragment and (
                (p.scheme == "https" and bool(p.netloc))
                or (p.scheme == "http" and p.hostname in ("localhost", "127.0.0.1", "::1"))))
        if not ok:
            raise InvalidRedirectUriError(
                f"Redirect URI '{uri}' is not allowed. Add it to oauth_redirect_uris.")
        return redirect_uri


class _FlexibleClientAuthenticator(ClientAuthenticator):
    """Accepts client_secret_basic and client_secret_post for every client.

    The SDK only accepts the one method a client registered with, which breaks
    fixed-credential clients whose method we can't know in advance.
    """

    async def authenticate_request(self, request: Request) -> OAuthClientInformationFull:
        form = await request.form()
        client_id = form.get("client_id")
        secret = form.get("client_secret")
        if not isinstance(client_id, str) or not client_id:
            raise AuthenticationError("Missing client_id")
        client = await self.provider.get_client(client_id)
        if not client:
            raise AuthenticationError("Invalid client_id")
        if not client.client_secret:  # public client (PKCE only)
            return client
        if not isinstance(secret, str) or not _eq(secret, client.client_secret):
            raise AuthenticationError("Invalid client_secret")
        if client.client_secret_expires_at and client.client_secret_expires_at < time.time():
            raise AuthenticationError("Client secret has expired")
        return client


async def _normalize_token_form(request: Request) -> None:
    """Fold HTTP Basic client credentials into the form the SDK reads."""
    form = await request.form()
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("basic "):
        return
    try:
        cid, _, sec = base64.b64decode(auth[6:].strip()).decode("utf-8").partition(":")
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return
    cid, sec = unquote(cid), unquote(sec)
    items = [(k, v) for k, v in form.multi_items() if k not in ("client_id", "client_secret")]
    if form.get("client_id") not in (None, "", cid):
        cid = "\x00mismatch"  # Basic and body disagree -> invalid_client
    items += [("client_id", cid), ("client_secret", sec)]
    request._form = FormData(items)


# ----------------------------------------------------------------- provider
class MealieOAuthProvider(OAuthProvider):
    def __init__(self, cfg: dict[str, Any] | None = None):
        cfg = cfg or oauth_settings()
        problems = config_problems(cfg)
        if problems:
            raise ValueError(" ".join(problems))
        super().__init__(
            base_url=cfg["public_url"],
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE]),
            revocation_options=RevocationOptions(enabled=True),
        )
        self.cfg = cfg
        self._lock = threading.Lock()
        self._codes: dict[str, AuthorizationCode] = {}
        self._pending: dict[str, dict[str, Any]] = {}
        self._fails: dict[str, list[float]] = {}
        self._clients: dict[str, dict] = {}
        self._access: dict[str, dict] = {}
        self._refresh: dict[str, dict] = {}
        self._state_file = self._state_path()
        self._load()

    # ------------------------------------------------------------ store
    @staticmethod
    def _state_path() -> Path:
        if os.getenv("MCP_OAUTH_STATE_FILE"):
            return Path(os.environ["MCP_OAUTH_STATE_FILE"])
        if Path("/data").is_dir() and os.access("/data", os.W_OK):
            return Path("/data/oauth_state.json")
        return Path.home() / ".mealie-mcp" / "oauth_state.json"

    def _load(self) -> None:
        try:
            data = json.loads(self._state_file.read_text())
        except Exception:
            return
        now = time.time()
        self._clients = data.get("clients", {})
        self._access = {k: v for k, v in data.get("access", {}).items() if (v.get("expires_at") or 0) > now}
        self._refresh = {k: v for k, v in data.get("refresh", {}).items() if (v.get("expires_at") or 0) > now}

    def _save(self) -> None:
        try:
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._state_file.with_suffix(".tmp")
            tmp.write_text(json.dumps({"clients": self._clients, "access": self._access,
                                       "refresh": self._refresh}))
            os.chmod(tmp, 0o600)
            tmp.replace(self._state_file)
        except Exception as e:
            log.warning("Could not persist OAuth state: %s", e)

    def _prune(self) -> None:
        now = time.time()
        self._access = {k: v for k, v in self._access.items() if (v.get("expires_at") or 0) > now}
        self._refresh = {k: v for k, v in self._refresh.items() if (v.get("expires_at") or 0) > now}
        self._codes = {k: v for k, v in self._codes.items() if v.expires_at > now}
        self._pending = {k: v for k, v in self._pending.items() if v["exp"] > now}

    def revoke_all(self) -> None:
        with self._lock:
            self._access.clear()
            self._refresh.clear()
            self._save()

    # ---------------------------------------------------------- clients
    def _static_client(self) -> _StaticClient | None:
        if not self.cfg["client_id"]:
            return None
        return _StaticClient(
            client_id=self.cfg["client_id"],
            client_secret=self.cfg["client_secret"],
            client_name="Pre-registered client",
            redirect_uris=None,
            token_endpoint_auth_method="client_secret_post",
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope=SCOPE,
        )

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        static = self._static_client()
        if static and _eq(client_id, static.client_id):
            return static
        data = self._clients.get(client_id)
        return _Client.model_validate(data) if data else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        with self._lock:
            if client_info.client_id == self.cfg["client_id"]:
                raise ValueError("client_id collision")
            self._clients[client_info.client_id] = client_info.model_dump(mode="json", exclude_none=True)
            while len(self._clients) > MAX_CLIENTS:  # drop the oldest registration
                self._clients.pop(next(iter(self._clients)))
            self._save()
        log.info("OAuth: registered client %s (%s)", client_info.client_name or "?", client_info.client_id)

    # ------------------------------------------------------- authorize
    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        txn = secrets.token_urlsafe(24)
        with self._lock:
            self._prune()
            self._pending[txn] = {"client_id": client.client_id,
                                  "params": params.model_dump(mode="json"),
                                  "exp": time.time() + CONSENT_TTL}
        return f"{self.cfg['public_url']}{CONSENT_PATH}?txn={txn}"

    def _throttled(self, ip: str) -> bool:
        now = time.time()
        recent = [t for t in self._fails.get(ip, []) if now - t < FAIL_WINDOW]
        self._fails[ip] = recent
        return len(recent) >= MAX_FAILS

    async def consent(self, request: Request) -> Response:
        if request.method == "POST":
            form = await request.form()
            txn, action, password = form.get("txn", ""), form.get("action", ""), form.get("password", "")
        else:
            txn, action, password = request.query_params.get("txn", ""), "", ""
        pending = self._pending.get(str(txn))
        if not pending or pending["exp"] < time.time():
            return _page("Request expired", "<p>This sign-in request has expired or was already "
                         "used. Start connecting again from your AI client.</p>", 400)
        client = await self.get_client(pending["client_id"])
        params = AuthorizationParams.model_validate(pending["params"])
        redirect = str(params.redirect_uri)
        name = (client.client_name if client else None) or pending["client_id"]

        if request.method == "GET":
            return _consent_form(str(txn), name, redirect)

        if action == "deny":
            self._pending.pop(str(txn), None)
            return RedirectResponse(construct_redirect_uri(redirect, error="access_denied",
                                                           state=params.state), 302)

        ip = request.headers.get("cf-connecting-ip") or (request.client.host if request.client else "?")
        if self._throttled(ip):
            return _consent_form(str(txn), name, redirect, "Too many attempts. Wait 10 minutes.", 429)
        if not _eq(str(password), self.cfg["password"]):
            self._fails.setdefault(ip, []).append(time.time())
            return _consent_form(str(txn), name, redirect, "Wrong password.", 401)

        code = secrets.token_urlsafe(32)
        with self._lock:
            self._pending.pop(str(txn), None)
            self._codes[code] = AuthorizationCode(
                code=code, scopes=params.scopes or [SCOPE], expires_at=time.time() + CODE_TTL,
                client_id=pending["client_id"], code_challenge=params.code_challenge,
                redirect_uri=params.redirect_uri,
                redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
                resource=params.resource)
        log.info("OAuth: approved %s", name)
        return RedirectResponse(construct_redirect_uri(redirect, code=code, state=params.state), 302)

    # ---------------------------------------------------------- tokens
    async def load_authorization_code(self, client, authorization_code: str) -> AuthorizationCode | None:
        code = self._codes.get(authorization_code)
        if code and code.client_id == client.client_id and code.expires_at > time.time():
            return code
        return None

    def _issue(self, client_id: str, scopes: list[str], resource: str | None) -> OAuthToken:
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        now = int(time.time())
        self._prune()
        base = {"client_id": client_id, "scopes": scopes, "resource": resource}
        self._access[_h(access)] = {**base, "expires_at": now + ACCESS_TTL}
        self._refresh[_h(refresh)] = {**base, "expires_at": now + REFRESH_TTL}
        self._save()
        return OAuthToken(access_token=access, token_type="Bearer", expires_in=ACCESS_TTL,
                          refresh_token=refresh, scope=" ".join(scopes) or None)

    async def exchange_authorization_code(self, client, authorization_code: AuthorizationCode) -> OAuthToken:
        with self._lock:
            if self._codes.pop(authorization_code.code, None) is None:
                from mcp.server.auth.provider import TokenError
                raise TokenError("invalid_grant", "authorization code was already used")
            return self._issue(client.client_id, authorization_code.scopes, authorization_code.resource)

    async def load_refresh_token(self, client, refresh_token: str) -> RefreshToken | None:
        data = self._refresh.get(_h(refresh_token))
        if not data or data["client_id"] != client.client_id or data["expires_at"] < time.time():
            return None
        return RefreshToken(token=refresh_token, **data)

    async def exchange_refresh_token(self, client, refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        with self._lock:
            self._refresh.pop(_h(refresh_token.token), None)  # rotate
            return self._issue(client.client_id, scopes or refresh_token.scopes, refresh_token.resource)

    async def load_access_token(self, token: str) -> AccessToken | None:
        static = self.cfg["static_token"]
        if static and _eq(token, static):
            return AccessToken(token=token, client_id=STATIC_BEARER_CLIENT, scopes=[SCOPE])
        data = self._access.get(_h(token))
        if not data or data["expires_at"] < time.time():
            return None
        return AccessToken(token=token, **data)

    async def revoke_token(self, token) -> None:
        with self._lock:
            self._access.pop(_h(token.token), None)
            self._refresh.pop(_h(token.token), None)
            self._save()

    # ---------------------------------------------------------- routes
    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        routes = []
        token_handler = TokenHandler(provider=self, client_authenticator=_FlexibleClientAuthenticator(self))

        async def token_endpoint(request: Request) -> Response:
            await _normalize_token_form(request)
            return await token_handler.handle(request)

        for route in super().get_routes(mcp_path):
            if isinstance(route, Route) and route.path == "/token":
                route = Route("/token", endpoint=cors_middleware(token_endpoint, ["POST", "OPTIONS"]),
                              methods=["POST", "OPTIONS"])
            routes.append(route)
        routes.append(Route(CONSENT_PATH, endpoint=self.consent, methods=["GET", "POST"]))
        return routes


# ----------------------------------------------------------------- pages
_CSS = """body{font-family:system-ui,sans-serif;background:#f4f4f5;margin:0;display:flex;
min-height:100vh;align-items:center;justify-content:center}.card{background:#fff;padding:28px;
border-radius:12px;box-shadow:0 2px 12px #0001;max-width:380px;width:90%}h1{font-size:20px;margin:0 0 8px}
p{color:#444;font-size:14px}input{width:100%;box-sizing:border-box;padding:10px;font-size:16px;
border:1px solid #ccc;border-radius:8px;margin:8px 0 14px}.row{display:flex;flex-direction:row-reverse;
gap:8px}button{flex:1;padding:10px;font-size:15px;border-radius:8px;border:0;cursor:pointer}
.ok{background:#e58325;color:#fff}.no{background:#e4e4e7}.err{color:#b91c1c;font-size:14px}"""


def _page(title: str, body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(
        f"<!doctype html><html><head><meta charset=utf-8><meta name=viewport "
        f"content='width=device-width,initial-scale=1'><title>{html.escape(title)}</title>"
        f"<style>{_CSS}</style></head><body><div class=card><h1>{html.escape(title)}</h1>"
        f"{body}</div></body></html>",
        status_code=status,
        headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY",
                 "Content-Security-Policy": "frame-ancestors 'none'"},
    )


def _consent_form(txn: str, name: str, redirect: str, error: str = "", status: int = 200) -> HTMLResponse:
    host = html.escape(urlparse(redirect).netloc or redirect)
    err = f"<p class=err>{html.escape(error)}</p>" if error else ""
    return _page("Connect to Mealie MCP", (
        f"<p><b>{html.escape(name)}</b> wants access to your Mealie recipes, meal plans and "
        f"shopping lists. After approval you'll be sent back to <b>{host}</b>.</p>"
        f"{err}<form method=post><input type=hidden name=txn value='{html.escape(txn, quote=True)}'>"
        "<label>Approval password<input type=password name=password autofocus "
        "autocomplete=current-password></label><div class=row>"
        "<button class=ok name=action value=allow>Allow</button>"
        "<button class=no name=action value=deny>Deny</button></div></form>"), status)
