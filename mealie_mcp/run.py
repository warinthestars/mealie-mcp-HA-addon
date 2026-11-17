"""
Home Assistant app entrypoint.

Reads the app options from /data/options.json (written by the Supervisor),
maps them to the environment variables the server expects, then starts the
MCP server over streamable HTTP. Outside Home Assistant (no options file),
plain environment variables are used as-is.
"""

import json
import os
import sys
from pathlib import Path

OPTIONS_FILE = Path("/data/options.json")

print(f"Mealie MCP Server app v{os.environ.get('APP_VERSION', 'dev')}", flush=True)

if OPTIONS_FILE.exists():
    opts = json.loads(OPTIONS_FILE.read_text())
    mapping = {
        "mealie_url": "MEALIE_URL",
        "mealie_api_token": "MEALIE_API_TOKEN",
        "mcp_auth_token": "MCP_AUTH_TOKEN",
        "log_level": "MCP_LOG_LEVEL",
        # FORK: built-in OAuth server (src/oauth.py)
        "oauth_enabled": "MCP_OAUTH_ENABLED",
        "public_url": "MCP_PUBLIC_URL",
        "oauth_client_id": "MCP_OAUTH_CLIENT_ID",
        "oauth_client_secret": "MCP_OAUTH_CLIENT_SECRET",
        "oauth_password": "MCP_OAUTH_PASSWORD",
        "oauth_redirect_uris": "MCP_OAUTH_REDIRECT_URIS",
    }
    for key, env in mapping.items():
        value = opts.get(key)
        if value not in (None, ""):
            os.environ[env] = str(value)

os.environ["MEALIE_URL"] = os.environ.get("MEALIE_URL", "").rstrip("/")

missing = [v for v in ("MEALIE_URL", "MEALIE_API_TOKEN") if not os.environ.get(v)]
if missing:
    print(f"ERROR: missing configuration: {', '.join(missing)}. "
          "Set them on the app's Configuration tab.", flush=True)
    sys.exit(1)

if not os.environ.get("MCP_AUTH_TOKEN") and os.environ.get(
        "MCP_OAUTH_ENABLED", "").lower() not in ("1", "true", "yes", "on"):
    print("WARNING: mcp_auth_token is empty - the MCP endpoint is open to "
          "anyone who can reach this port on your network.", flush=True)

os.environ.setdefault("MCP_TRANSPORT", "http")
sys.path.insert(0, "/app/src")

import server  # noqa: E402

server.main()
