"""
FORK: Web UI for the Mealie MCP server (Home Assistant "Open Web UI" / ingress).

Pages: Overview (server + Mealie status), Connect (client setup snippets),
Tools (enable/disable MCP tools, persisted), Library (data-quality counts and
audit), Backups (list / create).

Access control:
- Inside the Home Assistant app, the UI only answers requests proxied by the
  Supervisor's ingress (peer 172.30.32.2); HA has already authenticated the user.
- Elsewhere it answers loopback requests only, unless MCP_UI_ALLOW_REMOTE=1.
- MCP_UI_ENABLED=0 turns the UI off.
The MCP endpoint itself keeps its bearer-token protection (see http_transport).
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response

log = logging.getLogger("mealie_mcp.ui")

SUPERVISOR_INGRESS_IP = "172.30.32.2"
UI_PREFIX = "/ui/"
_STARTED = time.time()
_STATE: dict[str, Any] = {"tools": {}, "disabled": set()}

CATEGORY_RULES = [
    ("mealie_recipes_", "Recipes"),
    ("mealie_mealplan", "Meal plans"),
    ("mealie_shopping_", "Shopping lists"),
    ("mealie_foods_", "Foods & units"),
    ("mealie_units_", "Foods & units"),
    ("mealie_parser_", "Foods & units"),
    ("mealie_labels_", "Labels"),
    ("mealie_categories_", "Organizers"),
    ("mealie_tags_", "Organizers"),
    ("mealie_tools_", "Organizers"),
    ("mealie_cookbooks_", "Cookbooks"),
    ("mealie_comments_", "Comments & timeline"),
    ("mealie_timeline_", "Comments & timeline"),
    ("mealie_webhooks_", "Automation"),
    ("mealie_notifications_", "Automation"),
    ("mealie_recipe_actions_", "Automation"),
    ("mealie_backups_", "Admin"),
    ("mealie_api_", "Admin"),
]


# -----------------------------------------------------------------------------
# helpers
# -----------------------------------------------------------------------------

def in_addon() -> bool:
    return bool(os.getenv("SUPERVISOR_TOKEN")) or Path("/data/options.json").exists()


def _settings_path() -> Path:
    if os.getenv("MCP_UI_SETTINGS"):
        return Path(os.environ["MCP_UI_SETTINGS"])
    if Path("/data").is_dir() and os.access("/data", os.W_OK):
        return Path("/data/ui_settings.json")
    return Path.home() / ".mealie-mcp" / "ui_settings.json"


def _load_settings() -> dict:
    try:
        return json.loads(_settings_path().read_text())
    except Exception:
        return {}


def _save_settings(data: dict) -> None:
    path = _settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(path)


def _category(name: str) -> str:
    for prefix, cat in CATEGORY_RULES:
        if name.startswith(prefix):
            return cat
    return "Other"


def _allowed(request: Request) -> bool:
    if os.getenv("MCP_UI_ENABLED", "1") == "0":
        return False
    peer = request.client.host if request.client else ""
    if in_addon():
        return peer == SUPERVISOR_INGRESS_IP
    if os.getenv("MCP_UI_ALLOW_REMOTE") == "1":
        return True
    return peer in ("127.0.0.1", "::1", "localhost")


def _guard(handler):
    async def wrapped(request: Request) -> Response:
        if not _allowed(request):
            return JSONResponse(
                {"error": "The web UI is only available through Home Assistant (Open Web UI) "
                          "or from this machine. Set MCP_UI_ALLOW_REMOTE=1 to change that."},
                status_code=403,
            )
        try:
            return await handler(request)
        except Exception as e:  # never leak a stack trace into the UI
            log.exception("UI handler failed")
            return JSONResponse({"error": str(e)}, status_code=500)
    wrapped.__name__ = handler.__name__
    return wrapped


def _client():
    from client import MealieClient  # local import: env is read at call time
    return MealieClient()


def _total(client, path: str, params: dict | None = None) -> int | None:
    try:
        data = client.get(path, params={"page": 1, "perPage": 1, **(params or {})})
        return data.get("total") if isinstance(data, dict) else None
    except Exception:
        return None


def _server_version() -> str:
    import re
    text = (Path(__file__).with_name("__init__.py")).read_text()
    m = re.search(r'__version__\s*=\s*["\']([^"\']+)', text)
    return m.group(1) if m else "dev"


def _snapshot_tools(mcp) -> dict[str, dict]:
    """Capture every registered tool once, before any are disabled."""
    import asyncio
    tools = asyncio.run(mcp.list_tools())
    out = {}
    for t in tools:
        desc = (t.description or "").strip().split("\n\n")[0].replace("\n", " ")
        out[t.name] = {"name": t.name, "category": _category(t.name), "description": desc[:300]}
    return out


# -----------------------------------------------------------------------------
# registration
# -----------------------------------------------------------------------------

def register_ui(mcp) -> None:
    """Attach the web UI routes to the FastMCP server and apply saved tool settings."""
    if os.getenv("MCP_UI_ENABLED", "1") == "0":
        log.info("Web UI disabled (MCP_UI_ENABLED=0)")
        return
    if not hasattr(mcp, "custom_route"):
        log.warning("This fastmcp version has no custom_route; web UI not available")
        return

    _STATE["tools"] = _snapshot_tools(mcp)
    saved = _load_settings()
    disabled = {n for n in saved.get("disabled_tools", []) if n in _STATE["tools"]}
    if disabled and hasattr(mcp, "disable"):
        mcp.disable(names=disabled)
    _STATE["disabled"] = disabled
    server_version = _server_version()

    @mcp.custom_route("/", methods=["GET"])
    @_guard
    async def ui_index(request: Request) -> Response:
        return HTMLResponse(PAGE.replace("{{VERSION}}", server_version))

    @mcp.custom_route("/ui/api/status", methods=["GET"])
    @_guard
    async def ui_status(request: Request) -> Response:
        mealie: dict[str, Any] = {"url": os.getenv("MEALIE_URL", ""), "connected": False}
        try:
            with _client() as c:
                about = c.get("/api/app/about")
                mealie.update({"connected": True, "version": about.get("version"),
                               "production": about.get("production")})
                try:
                    me = c.get("/api/users/self")
                    mealie.update({"user": me.get("username") or me.get("fullName"),
                                   "admin": bool(me.get("admin"))})
                except Exception:
                    pass
        except Exception as e:
            mealie["error"] = str(e).splitlines()[0][:300]
        all_tools = _STATE["tools"]
        return JSONResponse({
            "server": {
                "version": server_version,
                "uptime_seconds": int(time.time() - _STARTED),
                "transport": os.getenv("MCP_TRANSPORT", "stdio"),
                "port": int(os.getenv("MCP_PORT", "8099")),
                "path": os.getenv("MCP_PATH", "/mcp"),
                "auth_enabled": bool(os.getenv("MCP_AUTH_TOKEN", "").strip()),
                "in_home_assistant": in_addon(),
                "hostname": os.getenv("HOSTNAME", ""),
            },
            "mealie": mealie,
            "tools": {"total": len(all_tools), "disabled": len(_STATE["disabled"])},
        })

    @mcp.custom_route("/ui/api/tools", methods=["GET"])
    @_guard
    async def ui_tools(request: Request) -> Response:
        rows = [{**t, "enabled": t["name"] not in _STATE["disabled"]} for t in _STATE["tools"].values()]
        rows.sort(key=lambda r: (r["category"], r["name"]))
        return JSONResponse({"tools": rows})

    @mcp.custom_route("/ui/api/tools", methods=["POST"])
    @_guard
    async def ui_tools_update(request: Request) -> Response:
        body = await request.json()
        names = set(_STATE["tools"])
        changes = body.get("changes") or [{"name": body.get("name"), "enabled": body.get("enabled")}]
        for ch in changes:
            name, enabled = ch.get("name"), bool(ch.get("enabled"))
            if name not in names:
                return JSONResponse({"error": f"unknown tool {name}"}, status_code=400)
            if enabled:
                _STATE["disabled"].discard(name)
                mcp.enable(names={name})
            else:
                _STATE["disabled"].add(name)
                mcp.disable(names={name})
        settings = _load_settings()
        settings["disabled_tools"] = sorted(_STATE["disabled"])
        _save_settings(settings)
        return JSONResponse({"ok": True, "disabled": sorted(_STATE["disabled"]),
                             "note": "Clients see the change after they refresh their tool list."})

    @mcp.custom_route("/ui/api/library", methods=["GET"])
    @_guard
    async def ui_library(request: Request) -> Response:
        with _client() as c:
            counts = {
                "recipes": _total(c, "/api/recipes"),
                "categories": _total(c, "/api/organizers/categories"),
                "tags": _total(c, "/api/organizers/tags"),
                "kitchen_tools": _total(c, "/api/organizers/tools"),
                "cookbooks": _total(c, "/api/households/cookbooks"),
                "foods": _total(c, "/api/foods"),
                "unlabeled_foods": _total(c, "/api/foods", {"queryFilter": "labelId IS NULL"}),
                "units": _total(c, "/api/units"),
                "labels": _total(c, "/api/groups/labels"),
                "shopping_lists": _total(c, "/api/households/shopping/lists"),
                "meal_plan_rules": _total(c, "/api/households/mealplans/rules"),
            }
        return JSONResponse({"counts": counts})

    @mcp.custom_route("/ui/api/audit", methods=["POST"])
    @_guard
    async def ui_audit(request: Request) -> Response:
        from tools.extended import recipes_audit
        import anyio
        result = await anyio.to_thread.run_sync(recipes_audit)
        return Response(result, media_type="application/json")

    @mcp.custom_route("/ui/api/backups", methods=["GET"])
    @_guard
    async def ui_backups(request: Request) -> Response:
        from tools.backups import backups_list
        return Response(backups_list(), media_type="application/json")

    @mcp.custom_route("/ui/api/backups", methods=["POST"])
    @_guard
    async def ui_backups_create(request: Request) -> Response:
        from tools.backups import backups_create
        import anyio
        return Response(await anyio.to_thread.run_sync(backups_create), media_type="application/json")

    log.info("Web UI enabled (%s)", "Home Assistant ingress only" if in_addon() else "local access")


# -----------------------------------------------------------------------------
# page
# -----------------------------------------------------------------------------

PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mealie MCP</title>
<style>
:root{--bg:#f5f6f8;--card:#fff;--text:#1d2329;--muted:#5f6b76;--line:#e3e7eb;--accent:#e58325;--accent-ink:#fff;--ok:#2e7d32;--bad:#c62828;--warn:#b26a00;--code:#f0f2f4}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--card:#1a1f25;--text:#e6e9ec;--muted:#9aa5b1;--line:#2a3139;--code:#232a32}}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text)}
header{display:flex;align-items:center;gap:12px;padding:16px 24px;background:var(--card);border-bottom:1px solid var(--line)}
header h1{font-size:18px;margin:0}header .ver{color:var(--muted);font-size:13px}
.logo{width:30px;height:30px;border-radius:8px;background:var(--accent);display:grid;place-items:center;color:var(--accent-ink);font-weight:700}
nav{display:flex;gap:4px;padding:0 24px;background:var(--card);border-bottom:1px solid var(--line);overflow-x:auto}
nav button{border:0;background:none;color:var(--muted);padding:12px 14px;font:inherit;cursor:pointer;border-bottom:2px solid transparent}
nav button.active{color:var(--text);border-bottom-color:var(--accent)}
main{max-width:1100px;margin:0 auto;padding:24px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px}
.card h2{font-size:15px;margin:0 0 10px}.muted{color:var(--muted)}
.kv{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;font-size:14px}.kv dt{color:var(--muted)}.kv dd{margin:0;word-break:break-all}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600}
.pill.ok{background:rgba(46,125,50,.14);color:var(--ok)}.pill.bad{background:rgba(198,40,40,.14);color:var(--bad)}.pill.warn{background:rgba(178,106,0,.15);color:var(--warn)}
.stat{font-size:28px;font-weight:700}.stat small{font-size:13px;font-weight:400;color:var(--muted);display:block}
button.btn{background:var(--accent);color:var(--accent-ink);border:0;border-radius:8px;padding:8px 14px;font:inherit;cursor:pointer}
button.btn.secondary{background:transparent;color:var(--text);border:1px solid var(--line)}button.btn:disabled{opacity:.6;cursor:default}
pre{background:var(--code);padding:12px;border-radius:8px;overflow:auto;font-size:13px;margin:8px 0 0;white-space:pre-wrap;word-break:break-all}
.snip{position:relative}.snip button{position:absolute;top:6px;right:6px;font-size:12px;padding:4px 8px}
input[type=text],input[type=search]{width:100%;padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--text);font:inherit}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}
.cat{margin-top:22px}.cat h3{font-size:14px;margin:0 0 6px;display:flex;justify-content:space-between;align-items:center}
.switch{position:relative;width:38px;height:22px;flex:none}.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;inset:0;background:var(--line);border-radius:22px;cursor:pointer;transition:.15s}.slider:before{content:"";position:absolute;width:16px;height:16px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.15s}
.switch input:checked+.slider{background:var(--accent)}.switch input:checked+.slider:before{transform:translateX(16px)}
.tool{display:flex;gap:12px;align-items:flex-start;padding:9px 0;border-bottom:1px solid var(--line)}.tool code{font-size:13px}.tool p{margin:2px 0 0;font-size:13px;color:var(--muted)}
.toast{position:fixed;bottom:18px;right:18px;background:var(--text);color:var(--bg);padding:10px 14px;border-radius:8px;opacity:0;transition:.2s}.toast.show{opacity:1}
.hidden{display:none}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
</style>
</head>
<body>
<header><div class="logo">M</div><div><h1>Mealie MCP Server</h1><div class="ver">v{{VERSION}}</div></div></header>
<nav id="tabs">
  <button data-tab="overview" class="active">Overview</button>
  <button data-tab="connect">Connect</button>
  <button data-tab="tools">Tools</button>
  <button data-tab="library">Library</button>
  <button data-tab="backups">Backups</button>
</nav>
<main>
<section id="overview">
  <div class="grid">
    <div class="card"><h2>Mealie</h2><dl class="kv" id="mealie-kv"><dt>Status</dt><dd>Checking…</dd></dl></div>
    <div class="card"><h2>MCP server</h2><dl class="kv" id="server-kv"></dl></div>
    <div class="card"><h2>Tools</h2><div class="stat" id="tool-stat">–</div><p class="muted" id="tool-note"></p></div>
  </div>
  <div class="card" style="margin-top:16px" id="warnings"></div>
  <div class="row" style="margin-top:16px"><button class="btn secondary" onclick="loadStatus()">Refresh</button></div>
</section>

<section id="connect" class="hidden">
  <div class="card">
    <h2>Server address</h2>
    <p class="muted">How your MCP client reaches this server. On your LAN this is usually your Home Assistant host's IP with port <span id="port-hint">8099</span>. For claude.ai custom connectors, use a public HTTPS URL (for example a Cloudflare tunnel) that points at this port.</p>
    <input type="text" id="mcp-url">
    <p class="muted" style="margin-top:8px">Bearer token: <span id="auth-hint"></span></p>
  </div>
  <div class="grid" style="margin-top:16px">
    <div class="card"><h2>Claude Code</h2><div class="snip"><button class="btn secondary" onclick="copy('snip-cc')">Copy</button><pre id="snip-cc"></pre></div></div>
    <div class="card"><h2>Claude Desktop (claude_desktop_config.json)</h2><div class="snip"><button class="btn secondary" onclick="copy('snip-cd')">Copy</button><pre id="snip-cd"></pre></div></div>
    <div class="card"><h2>claude.ai custom connector / other clients</h2><div class="snip"><button class="btn secondary" onclick="copy('snip-gen')">Copy</button><pre id="snip-gen"></pre></div></div>
  </div>
</section>

<section id="tools" class="hidden">
  <div class="card">
    <div class="row"><input type="search" id="tool-search" placeholder="Search tools…" style="flex:1"><span class="muted" id="tool-count"></span></div>
    <p class="muted" style="margin:8px 0 0">Turned-off tools are hidden from MCP clients. Clients pick up changes when they refresh their tool list or reconnect. Settings survive restarts and updates.</p>
    <div id="tool-list"></div>
  </div>
</section>

<section id="library" class="hidden">
  <div class="grid" id="lib-grid"></div>
  <div class="card" style="margin-top:16px">
    <div class="row"><h2 style="margin:0;flex:1">Recipe audit</h2><button class="btn" id="audit-btn" onclick="runAudit()">Run audit</button></div>
    <p class="muted">Checks every recipe for unparsed ingredients and missing images, descriptions, categories, tags, tools, servings, times and source URLs. Takes a few seconds per 50 recipes.</p>
    <div id="audit-out"></div>
  </div>
</section>

<section id="backups" class="hidden">
  <div class="card">
    <div class="row"><h2 style="margin:0;flex:1">Mealie backups</h2><button class="btn" id="backup-btn" onclick="createBackup()">Create backup</button></div>
    <p class="muted">Needs an admin Mealie API token. Restore from Mealie's own admin page.</p>
    <div id="backup-list">Loading…</div>
  </div>
</section>
</main>
<div class="toast" id="toast"></div>
<script>
const $=s=>document.querySelector(s);let STATUS=null,TOOLS=[];
function toast(m){const t=$('#toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2500)}
function esc(s){return String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
async function api(p,o){const r=await fetch('ui/api/'+p,o);const j=await r.json().catch(()=>({error:'Bad response'}));if(!r.ok||j.error)throw new Error(j.error||r.statusText);return j}
function copy(id){navigator.clipboard.writeText($('#'+id).textContent).then(()=>toast('Copied'))}
document.querySelectorAll('#tabs button').forEach(b=>b.onclick=()=>{document.querySelectorAll('#tabs button').forEach(x=>x.classList.toggle('active',x===b));document.querySelectorAll('main>section').forEach(s=>s.classList.toggle('hidden',s.id!==b.dataset.tab));({tools:loadTools,library:loadLibrary,backups:loadBackups}[b.dataset.tab]||(()=>{}))()});
function fmtUp(s){const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return (d?d+'d ':'')+(h?h+'h ':'')+m+'m'}
async function loadStatus(){
  try{STATUS=await api('status')}catch(e){$('#mealie-kv').innerHTML='<dt>Error</dt><dd>'+esc(e.message)+'</dd>';return}
  const m=STATUS.mealie,s=STATUS.server;
  $('#mealie-kv').innerHTML=`<dt>Status</dt><dd>${m.connected?'<span class="pill ok">Connected</span>':'<span class="pill bad">Not connected</span>'}</dd>
   <dt>URL</dt><dd>${esc(m.url)}</dd>${m.version?`<dt>Version</dt><dd>${esc(m.version)}</dd>`:''}
   ${m.user?`<dt>Token user</dt><dd>${esc(m.user)} ${m.admin?'<span class="pill ok">admin</span>':'<span class="pill warn">not admin</span>'}</dd>`:''}
   ${m.error?`<dt>Error</dt><dd>${esc(m.error)}</dd>`:''}`;
  $('#server-kv').innerHTML=`<dt>Version</dt><dd>${esc(s.version)}</dd><dt>Uptime</dt><dd>${fmtUp(s.uptime_seconds)}</dd>
   <dt>Endpoint</dt><dd>:${s.port}${esc(s.path)}</dd><dt>Auth</dt><dd>${s.auth_enabled?'<span class="pill ok">Bearer token</span>':'<span class="pill bad">None</span>'}</dd>`;
  $('#tool-stat').innerHTML=`${STATUS.tools.total-STATUS.tools.disabled}<small>of ${STATUS.tools.total} tools enabled</small>`;
  const w=[];if(!s.auth_enabled)w.push('No MCP bearer token is set, so anyone who can reach port '+s.port+' can use this server. Set one on the app\'s Configuration tab.');
  if(!m.connected)w.push('The server cannot reach Mealie. Check the Mealie URL and API token on the Configuration tab.');
  if(m.connected&&m.user&&!m.admin)w.push('The Mealie token is not an admin token, so the backup tools will not work.');
  $('#warnings').innerHTML=w.length?'<h2>Attention</h2>'+w.map(x=>'<p>⚠️ '+esc(x)+'</p>').join(''):'<h2>All good</h2><p class="muted">No problems found.</p>';
  $('#port-hint').textContent=s.port;
  const host=(location.hostname&&!location.hostname.includes('hassio'))?location.hostname:'homeassistant.local';
  if(!$('#mcp-url').value)$('#mcp-url').value=`http://${host}:${s.port}${s.path}`;
  $('#auth-hint').innerHTML=s.auth_enabled?'set. Use the value from the app\'s Configuration tab where the snippets say <code>YOUR_TOKEN</code>.':'<span class="pill bad">not set</span>, so the snippets omit it.';
  renderSnippets();
}
function renderSnippets(){
  if(!STATUS)return;const url=$('#mcp-url').value.trim(),auth=STATUS.server.auth_enabled;
  $('#snip-cc').textContent=`claude mcp add --transport http mealie ${url}`+(auth?` \\\n  --header "Authorization: Bearer YOUR_TOKEN"`:'');
  const args=['-y','mcp-remote',url];if(auth)args.push('--header','Authorization: Bearer YOUR_TOKEN');
  $('#snip-cd').textContent=JSON.stringify({mcpServers:{mealie:{command:'npx',args}}},null,2);
  $('#snip-gen').textContent=`URL:       ${url}\nTransport: Streamable HTTP`+(auth?`\nHeader:    Authorization: Bearer YOUR_TOKEN`:'');
}
$('#mcp-url').addEventListener('input',renderSnippets);
async function loadTools(){
  try{TOOLS=(await api('tools')).tools}catch(e){$('#tool-list').innerHTML='<p>'+esc(e.message)+'</p>';return}renderTools()}
function renderTools(){
  const q=$('#tool-search').value.toLowerCase();const groups={};
  TOOLS.filter(t=>!q||t.name.includes(q)||t.description.toLowerCase().includes(q)).forEach(t=>(groups[t.category]=groups[t.category]||[]).push(t));
  $('#tool-count').textContent=`${TOOLS.filter(t=>t.enabled).length} / ${TOOLS.length} enabled`;
  $('#tool-list').innerHTML=Object.entries(groups).map(([cat,ts])=>`<div class="cat"><h3>${esc(cat)} <span class="row"><button class="btn secondary" onclick="setGroup('${esc(cat)}',true)">All on</button><button class="btn secondary" onclick="setGroup('${esc(cat)}',false)">All off</button></span></h3>`+
   ts.map(t=>`<div class="tool"><label class="switch"><input type="checkbox" ${t.enabled?'checked':''} onchange="setTool('${t.name}',this.checked)"><span class="slider"></span></label><div><code>${esc(t.name)}</code><p>${esc(t.description)}</p></div></div>`).join('')+'</div>').join('');
}
$('#tool-search').addEventListener('input',renderTools);
async function save(changes){try{await api('tools',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({changes})});changes.forEach(c=>{const t=TOOLS.find(x=>x.name===c.name);if(t)t.enabled=c.enabled});renderTools();toast('Saved')}catch(e){toast(e.message);loadTools()}}
function setTool(n,on){save([{name:n,enabled:on}])}
function setGroup(cat,on){save(TOOLS.filter(t=>t.category===cat).map(t=>({name:t.name,enabled:on})))}
const LIB=[['recipes','Recipes'],['categories','Categories'],['tags','Tags'],['kitchen_tools','Kitchen tools'],['cookbooks','Cookbooks'],['foods','Foods'],['unlabeled_foods','Foods without a label'],['units','Units'],['labels','Labels'],['shopping_lists','Shopping lists'],['meal_plan_rules','Meal plan rules']];
async function loadLibrary(){$('#lib-grid').innerHTML='<div class="card">Loading…</div>';try{const c=(await api('library')).counts;$('#lib-grid').innerHTML=LIB.map(([k,l])=>`<div class="card"><div class="stat">${c[k]??'–'}<small>${l}</small></div></div>`).join('')}catch(e){$('#lib-grid').innerHTML='<div class="card">'+esc(e.message)+'</div>'}}
const FLAGS={unparsed_ingredients:'Unparsed ingredients',no_image:'No image',no_description:'No description',no_category:'No category',no_tags:'No tags',no_tools:'No kitchen tools',no_servings:'No servings',no_total_time:'No total time',no_source_url:'No source URL'};
async function runAudit(){const b=$('#audit-btn');b.disabled=true;b.textContent='Running…';
  try{const r=await api('audit',{method:'POST'});const fc=r.flag_counts||{};
   let h='<div class="grid" style="margin-top:12px">'+Object.entries(FLAGS).map(([k,l])=>`<div class="card"><div class="stat">${fc[k]||0}<small>${l}</small></div></div>`).join('')+'</div>';
   const bad=r.recipes.filter(x=>x.flags.some(f=>!['no_tools','no_source_url'].includes(f.split(':')[0])));
   h+=`<h3 style="margin-top:18px">Recipes needing attention (${bad.length} of ${r.total})</h3><table><tr><th>Recipe</th><th>Issues</th></tr>`+bad.map(x=>`<tr><td>${esc(x.name)}</td><td>${x.flags.map(f=>{const[k,v]=f.split(':');return `<span class="pill warn">${esc(FLAGS[k]||k)}${v?' '+esc(v):''}</span>`}).join(' ')}</td></tr>`).join('')+'</table>';
   $('#audit-out').innerHTML=h}catch(e){$('#audit-out').textContent=e.message}b.disabled=false;b.textContent='Run audit'}
async function loadBackups(){try{const r=await api('backups');$('#backup-list').innerHTML=r.backups.length?'<table><tr><th>File</th><th>Date</th><th>Size</th></tr>'+r.backups.map(b=>`<tr><td>${esc(b.name)}</td><td>${esc((b.date||'').replace('T',' ').slice(0,19))}</td><td>${esc(b.size)}</td></tr>`).join('')+'</table>':'<p class="muted">No backups yet.</p>'}catch(e){$('#backup-list').textContent=e.message}}
async function createBackup(){const b=$('#backup-btn');b.disabled=true;b.textContent='Creating…';try{await api('backups',{method:'POST'});toast('Backup created');loadBackups()}catch(e){toast(e.message)}b.disabled=false;b.textContent='Create backup'}
loadStatus();
</script>
</body>
</html>
"""
