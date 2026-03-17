import json
import os
import time
from pathlib import Path

import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
from starlette.types import ASGIApp, Receive, Scope, Send

from .audit import AuditEntry, AuditLog
from .auth import AWSAuthManager
from .policy import PolicyEngine
from .routes import aws, git, gmail, slack

# Configuration
MANIFEST_PATH = os.environ.get("YOLO_PROJECT_MANIFEST", "")
AUDIT_DB_PATH = os.environ.get("YOLO_AUDIT_DB", "/data/audit.db")
AWS_CONFIG_PATH = os.environ.get("AWS_CONFIG_FILE", "/root/.aws/config")
PROJECTS_DIR = os.environ.get("YOLO_PROJECTS_DIR", "/projects")

# Optional API key auth — if set, all requests must include Authorization: Bearer <key>
# Multiple keys supported (comma-separated)
API_KEYS = [k.strip() for k in os.environ.get("YOLO_API_KEYS", "").split(",") if k.strip()]

# Core components
policy = PolicyEngine(MANIFEST_PATH if MANIFEST_PATH else None)
audit = AuditLog(AUDIT_DB_PATH)
aws_auth = AWSAuthManager(AWS_CONFIG_PATH)

# Multi-project support: cache PolicyEngine per project name
_project_policies: dict[str, PolicyEngine] = {}


def get_policy_for_project(project_name: str) -> PolicyEngine:
    """Get or create a PolicyEngine for a project. Cached after first load."""
    if project_name in _project_policies:
        return _project_policies[project_name]
    manifest_path = os.path.join(PROJECTS_DIR, f"{project_name}.yml")
    if not os.path.exists(manifest_path):
        return policy
    pe = PolicyEngine(manifest_path)
    _project_policies[project_name] = pe
    return pe


app = FastAPI(title="YOLO Gateway", description="Policy-based access gateway for Claude Code — AWS, Git, Slack, Gmail")
app.state.audit = audit


@app.on_event("startup")
async def startup():
    """Check SSO status and auto-pull repos on startup."""
    if not policy.has_project:
        print("  Gateway started in standalone mode (no active project)")
        print("  Dashboard: http://localhost:9000/dashboard")
        print(f"  Manifests dir: {PROJECTS_DIR}")
        return

    accounts = policy.get_aws_accounts()
    for acct in accounts:
        account_id = acct.get("account", "")
        acct_name = acct.get("name", account_id)
        sso_role = acct.get("sso_role", "")
        if not account_id:
            continue
        try:
            status = aws_auth.check_account(account_id, sso_role=sso_role)
        except Exception as e:
            print(f"  SSO check failed for {acct_name}: {e}")
            continue
        if status.get("status") == "expired":
            print(f"  SSO EXPIRED for {acct_name} ({account_id})")
            try:
                result = aws_auth.start_sso_login(account_id)
                url = result.get("verification_url", "")
                if url:
                    print(f"  OPEN TO AUTH: {url}")
            except Exception as e:
                print(f"  SSO login failed: {e}")
        elif status.get("status") == "no_profile":
            print(f"  No SSO profile for {acct_name} ({account_id})")
        elif status.get("status") == "active":
            print(f"  SSO active for {acct_name} ({account_id})")

    # Auto-pull repos from manifest
    repos = policy.get_git_repos()
    if repos:
        print(f"\n  Pulling repos in /workspace/...")
        try:
            git.auto_clone_repos(repos, audit=audit, project=policy.project_name)
        except Exception as e:
            print(f"  Auto-pull failed: {e}")
        print()


# ══════════════════════════════════════════
# Audit Middleware (pure ASGI — no deadlocks)
# ══════════════════════════════════════════


class AuditMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")

        # API key auth — skip for health check and docs
        if API_KEYS and path not in ("/health", "/docs", "/openapi.json"):
            headers = dict(scope.get("headers", []))
            auth_header = headers.get(b"authorization", b"").decode()
            token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else ""
            if token not in API_KEYS:
                response_body = json.dumps({"detail": "Invalid or missing API key"}).encode()
                await send({"type": "http.response.start", "status": 401,
                            "headers": [[b"content-type", b"application/json"]]})
                await send({"type": "http.response.body", "body": response_body})
                return

        scope.setdefault("state", {})

        # Multi-project: resolve policy from X-Project header
        headers = dict(scope.get("headers", []))
        project_header = headers.get(b"x-project", b"").decode()

        if project_header:
            scope["state"]["policy"] = get_policy_for_project(project_header)
        else:
            scope["state"]["policy"] = policy

        scope["state"]["aws_auth"] = aws_auth
        scope["state"]["audit"] = audit

        path = scope["path"]
        # Skip auditing for non-proxied endpoints
        if path in ("/", "/health") or path.startswith(("/dashboard", "/api/", "/auth/", "/favicon", "/docs", "/openapi")):
            return await self.app(scope, receive, send)

        start = time.time()

        # Capture request body
        request_body_bytes = b""
        request_received = False

        async def receive_wrapper():
            nonlocal request_body_bytes, request_received
            msg = await receive()
            if msg["type"] == "http.request" and not request_received:
                request_body_bytes = msg.get("body", b"")
                request_received = True
            return msg

        # Capture response
        status_code = 200
        response_body_parts = []

        async def send_wrapper(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            elif message["type"] == "http.response.body":
                body = message.get("body", b"")
                if body:
                    response_body_parts.append(body)
            await send(message)

        try:
            await self.app(scope, receive_wrapper, send_wrapper)
            elapsed_ms = int((time.time() - start) * 1000)

            try:
                request_body = json.loads(request_body_bytes) if request_body_bytes else None
            except (json.JSONDecodeError, UnicodeDecodeError):
                request_body = {"raw": request_body_bytes.decode("utf-8", errors="replace")[:2048]}

            response_body = None
            raw_response = b"".join(response_body_parts)
            try:
                response_body = json.loads(raw_response)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

            decision = "DENIED" if status_code == 403 else \
                       "SSO_EXPIRED" if status_code == 401 else \
                       "ERROR" if status_code >= 500 else "ALLOWED"

            action = _extract_action(path, request_body)
            error_msg = None
            if decision != "ALLOWED" and isinstance(response_body, dict):
                error_msg = response_body.get("detail", response_body.get("error"))

            audit.log(AuditEntry(
                project=scope["state"]["policy"].project_name,
                decision=decision,
                action=action,
                request_method=scope["method"],
                request_path=path,
                request_body=request_body,
                response_status=status_code,
                response_body=response_body,
                response_time_ms=elapsed_ms,
                error_message=str(error_msg) if error_msg else None,
            ))

        except Exception as e:
            elapsed_ms = int((time.time() - start) * 1000)
            try:
                request_body = json.loads(request_body_bytes) if request_body_bytes else None
            except (json.JSONDecodeError, UnicodeDecodeError):
                request_body = None
            audit.log(AuditEntry(
                project=scope["state"]["policy"].project_name,
                decision="ERROR",
                action=_extract_action(path, request_body),
                request_method=scope["method"],
                request_path=path,
                request_body=request_body,
                response_status=500,
                response_body={"error": str(e)},
                response_time_ms=elapsed_ms,
                error_message=str(e),
            ))
            raise


def _extract_action(path: str, body: dict | None) -> str:
    if path == "/aws" and isinstance(body, dict):
        return f"aws:{body.get('service', '')}:{body.get('action', '')}"
    if path.startswith("/git") and isinstance(body, dict):
        return f"git:{body.get('action', path.split('/')[-1])}:{body.get('repo', '')}"
    if path == "/slack" and isinstance(body, dict):
        return f"slack:{body.get('method', '')}"
    if path == "/gmail" and isinstance(body, dict):
        return f"gmail:{body.get('method', '')}"
    return path


app.add_middleware(AuditMiddleware)
app.include_router(aws.router)
app.include_router(git.router)
app.include_router(slack.router)
app.include_router(gmail.router)


# ══════════════════════════════════════════
# Core Endpoints
# ══════════════════════════════════════════


@app.get("/health")
async def health():
    """Health check — no auth required."""
    return {"status": "ok", "project": policy.project_name if policy.has_project else None}


@app.get("/")
async def root():
    return RedirectResponse("/dashboard")


@app.get("/whoami")
async def whoami():
    if not policy.has_project:
        return {"status": "no_active_project", "message": "Gateway running in standalone mode. Use POST /api/activate to select a project."}
    return policy.describe_permissions()


@app.get("/auth/status")
async def auth_status(account: str = ""):
    """Check SSO status for one or all accounts."""
    accounts = policy.get_aws_accounts()
    if not accounts:
        return {"status": "no_account_configured"}

    if account:
        acct = next((a for a in accounts if a.get("account") == account), None)
        if not acct:
            return {"status": "error", "error": f"Account {account} not in manifest"}
        return aws_auth.check_account(acct["account"], sso_role=acct.get("sso_role", ""))

    results = []
    all_active = True
    for acct in accounts:
        result = aws_auth.check_account(acct.get("account", ""), sso_role=acct.get("sso_role", ""))
        result["name"] = acct.get("name", acct.get("account", ""))
        results.append(result)
        if result.get("status") != "active":
            all_active = False

    return {"status": "all_active" if all_active else "needs_login", "accounts": results}


@app.post("/auth/login")
async def auth_login(account: str = ""):
    """Start SSO login for one or first expired account."""
    accounts = policy.get_aws_accounts()
    if not accounts:
        return {"status": "error", "error": "No AWS account configured"}

    if account:
        acct = next((a for a in accounts if a.get("account") == account), None)
        if not acct:
            return {"status": "error", "error": f"Account {account} not in manifest"}
        return aws_auth.start_sso_login(acct["account"], sso_role=acct.get("sso_role", ""))

    for acct in accounts:
        status = aws_auth.check_account(acct.get("account", ""), sso_role=acct.get("sso_role", ""))
        if status.get("status") != "active":
            return aws_auth.start_sso_login(acct["account"], sso_role=acct.get("sso_role", ""))

    return {"status": "all_active", "message": "All accounts already authenticated"}


@app.get("/auth/login/status")
async def auth_login_status(account: str = ""):
    accounts = policy.get_aws_accounts()
    if not accounts:
        return {"status": "error", "error": "No AWS account configured"}
    if account:
        return aws_auth.get_login_state(account)
    return {acct.get("account", ""): aws_auth.get_login_state(acct.get("account", "")) for acct in accounts}


# ══════════════════════════════════════════
# Dashboard
# ══════════════════════════════════════════


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    template_path = os.path.join(os.path.dirname(__file__), "templates", "dashboard.html")
    with open(template_path) as f:
        return f.read()


@app.get("/api/logs")
async def get_logs(
    project: str | None = None,
    decision: str | None = None,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
):
    return audit.query(project=project, decision=decision, search=search, limit=limit, offset=offset)


@app.get("/api/logs/{entry_id}")
async def get_log_detail(entry_id: int):
    entry = audit.get_entry(entry_id)
    if not entry:
        raise HTTPException(404, "Not found")
    return entry


@app.get("/api/stats")
async def get_stats():
    accounts = policy.get_aws_accounts()
    sso_accounts = []
    for acct in accounts:
        account_id = acct.get("account", "")
        if account_id:
            result = aws_auth.check_account(account_id, sso_role=acct.get("sso_role", ""))
            result["name"] = acct.get("name", account_id)
            sso_accounts.append(result)
    all_active = all(a.get("status") == "active" for a in sso_accounts) if sso_accounts else True
    return {
        "project": policy.project_name,
        "total_requests": audit.count(),
        "last_hour": audit.count(since_minutes=60),
        "denied_last_hour": audit.count(since_minutes=60, decision="DENIED"),
        "errors_last_hour": audit.count(since_minutes=60, decision="ERROR"),
        "avg_response_ms": audit.avg_response_time(since_minutes=60),
        "by_project": audit.count_by("project"),
        "by_decision": audit.count_by("decision"),
        "by_service": audit.count_by("action_prefix"),
        "sso_status": {"status": "all_active" if all_active else "needs_login", "accounts": sso_accounts},
    }


# ══════════════════════════════════════════
# Manifest Management
# ══════════════════════════════════════════


@app.get("/api/projects")
async def get_projects():
    return {policy.project_name: policy.describe_permissions()}


def _active_manifest_path() -> str:
    return policy._manifest_path or ""


@app.get("/api/manifest")
async def get_manifest(project: str = ""):
    if project:
        path = os.path.join(PROJECTS_DIR, f"{project}.yml")
    else:
        path = _active_manifest_path()
    if not path or not os.path.exists(path):
        raise HTTPException(404, f"No manifest for project '{project}'")
    with open(path) as f:
        raw_yaml = f.read()
    parsed = yaml.safe_load(raw_yaml)
    proj_name = parsed.get("project", {}).get("name", project or "unknown")
    active_path = _active_manifest_path()
    is_active = bool(active_path) and (os.path.abspath(path) == os.path.abspath(active_path))
    return {
        "project": proj_name,
        "path": path,
        "yaml": raw_yaml,
        "active": is_active,
        "permissions": PolicyEngine(path).describe_permissions() if not is_active else policy.describe_permissions(),
    }


@app.get("/api/manifests")
async def list_manifests():
    projects = []
    active_path = _active_manifest_path()
    for f in sorted(Path(PROJECTS_DIR).glob("*.yml")):
        try:
            with open(f) as fh:
                parsed = yaml.safe_load(fh.read())
            name = parsed.get("project", {}).get("name", f.stem)
            desc = parsed.get("project", {}).get("description", "")
            is_active = bool(active_path) and (os.path.abspath(str(f)) == os.path.abspath(active_path))
            projects.append({"file": f.stem, "name": name, "description": desc, "active": is_active})
        except Exception:
            projects.append({"file": f.stem, "name": f.stem, "description": "error reading", "active": False})
    return projects


class ManifestUpdate(BaseModel):
    yaml: str
    project: str = ""


@app.put("/api/manifest")
async def update_manifest(req: ManifestUpdate):
    try:
        parsed = yaml.safe_load(req.yaml)
    except yaml.YAMLError as e:
        raise HTTPException(400, f"Invalid YAML: {e}")

    if not isinstance(parsed, dict) or "project" not in parsed:
        raise HTTPException(400, "Manifest must have a 'project' section")

    if req.project:
        path = os.path.join(PROJECTS_DIR, f"{req.project}.yml")
    else:
        active = _active_manifest_path()
        if not active:
            raise HTTPException(400, "No active project — specify project name")
        path = active

    with open(path, "w") as f:
        f.write(req.yaml)

    active_path = _active_manifest_path()
    is_active = bool(active_path) and (os.path.abspath(path) == os.path.abspath(active_path))
    if is_active:
        policy.reload()

    return {"status": "saved", "active": is_active, "permissions": PolicyEngine(path).describe_permissions()}


class ManifestCreate(BaseModel):
    name: str
    yaml: str


@app.post("/api/manifest")
async def create_manifest(req: ManifestCreate):
    try:
        yaml.safe_load(req.yaml)
    except yaml.YAMLError as e:
        raise HTTPException(400, f"Invalid YAML: {e}")

    path = os.path.join(PROJECTS_DIR, f"{req.name}.yml")
    if os.path.exists(path):
        raise HTTPException(409, f"Project '{req.name}' already exists")

    with open(path, "w") as f:
        f.write(req.yaml)

    return {"status": "created", "project": req.name}


class ActivateProject(BaseModel):
    project: str


@app.post("/api/activate")
async def activate_project(req: ActivateProject):
    """Switch the active project manifest at runtime."""
    path = os.path.join(PROJECTS_DIR, f"{req.project}.yml")
    if not os.path.exists(path):
        raise HTTPException(404, f"No manifest for project '{req.project}'")
    policy.set_active_project(path)
    _project_policies.pop(req.project, None)
    aws_auth._session_cache.clear()
    return {"status": "activated", "project": req.project, "permissions": policy.describe_permissions()}


# ══════════════════════════════════════════
# Hook Message (for Claude prompt-submit hooks)
# ══════════════════════════════════════════

DEFAULT_HOOK_MESSAGE = """═══ GATEWAY RULES ═══
- ALL AWS access goes through: curl $GATEWAY_URL/aws
- ALL git push goes through: curl $GATEWAY_URL/git/push
- ALL Slack messages go through: curl $GATEWAY_URL/slack
- ALL Gmail access goes through: curl $GATEWAY_URL/gmail
- NEVER install AWS CLI or configure credentials
- NEVER git push directly — always use the gateway
- GET /whoami to see your permissions
- 403 = outside your scope, do not retry
- All operations are audited
═══════════════════════"""


@app.get("/api/hook-message")
async def get_hook_message(project: str = ""):
    if project:
        path = os.path.join(PROJECTS_DIR, f"{project}.yml")
        if os.path.exists(path):
            with open(path) as f:
                parsed = yaml.safe_load(f)
            custom = parsed.get("hook_message", "")
            if custom and custom.strip():
                return {"message": custom.strip(), "source": "manifest"}
    elif policy.has_project:
        raw = policy._policy.get("hook_message", "")
        if raw and raw.strip():
            return {"message": raw.strip(), "source": "manifest"}
    return {"message": DEFAULT_HOOK_MESSAGE.strip(), "source": "default"}
