# YOLO Gateway

**Policy-based access gateway for AI coding agents.** Control what your agent can touch — AWS, Git, Slack, Gmail — through simple YAML manifests. Every request is policy-checked, audited, and logged.

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│              │     │                  │     │  AWS (any svc)  │
│  Claude Code │────▶│  YOLO Gateway    │────▶│  Git (BB/SSH)   │
│              │     │                  │     │  Slack           │
│  ZERO keys   │◀────│  Policy Engine   │     │  Gmail           │
│  ZERO creds  │     │  Audit Log       │     │  + more coming   │
│  ZERO access │     │  API Key Auth    │     └─────────────────┘
│              │     │                  │
│              │     │  YAML Manifests  │     ┌─────────────────┐
│              │     │  define what's   │────▶│  SQLite Audit    │
│              │     │  allowed         │     │  (every request) │
└─────────────┘     └──────────────────┘     └─────────────────┘
```

Claude Code gets **zero credentials**. It talks to the gateway over HTTP. The gateway checks your YAML policy, proxies allowed calls to real services, denies everything else, and logs it all.

## Why

Claude Code with `--dangerously-skip-permissions` is powerful but dangerous with raw credentials. Give it your AWS keys and it might delete your production database. Give it your Gmail token and it might email your clients nonsense.

YOLO Gateway solves this:
- **You define the rules** in a YAML manifest (which services, which actions, which resources)
- **The gateway enforces them** — Claude never sees credentials
- **Everything is audited** — full request/response bodies in SQLite
- **Dashboard shows it all** — real-time web UI at localhost:9000

## Quick Start

```bash
git clone https://github.com/SideChannelLabs/yolo-gateway.git
cd yolo-gateway

# Configure credentials (agent never sees these)
cp .env.example .env
# Edit .env with your tokens

# Create a project policy (or use the example)
cp projects/example-project.yml projects/my-project.yml

# Run
docker compose up -d

# Open dashboard
open http://localhost:9000/dashboard
```

## Supported Services

### AWS (any service)
```bash
curl localhost:9000/aws -H "Content-Type: application/json" -d '{
  "service": "s3",
  "action": "ListBuckets",
  "params": {},
  "account": "123456789012"
}'
```
- Multi-account support with per-account service/action whitelists
- AWS SSO authentication (OIDC device flow, auto-login)
- Resource constraints (e.g., only allow specific CodeBuild projects)

### Git (Bitbucket + more coming)
```bash
curl localhost:9000/git/clone -H "Content-Type: application/json" -d '{"repo": "org/repo", "branch": "main"}'
curl localhost:9000/git/push  -H "Content-Type: application/json" -d '{"repo": "org/repo", "branch": "feature/x"}'
curl localhost:9000/git/pr    -H "Content-Type: application/json" -d '{"repo": "org/repo", "source_branch": "feature/x", "title": "My PR", "watch": true}'
```
- Branch restrictions with glob patterns (allow `feature/*`, deny `main`)
- PR creation with auto-watch for merge
- Repo creation with branch protection
- Path traversal protection on all git operations

### Slack
```bash
curl localhost:9000/slack -H "Content-Type: application/json" -d '{"method": "chat.postMessage", "params": {"channel": "#deploys", "text": "Build complete"}}'
curl localhost:9000/slack -H "Content-Type: application/json" -d '{"method": "conversations.list", "params": {}}'
curl localhost:9000/slack -H "Content-Type: application/json" -d '{"method": "conversations.history", "params": {"channel": "C01234"}}'
```
- Channel restrictions with glob patterns (allow `#engineering`, deny `#executive`)
- Read/write access levels
- Supported: `chat.postMessage`, `conversations.list/history/info`, `reactions.add`, `users.list/info`, `files.upload`

### Gmail
```bash
curl localhost:9000/gmail -H "Content-Type: application/json" -d '{"method": "messages.list", "params": {"q": "is:unread", "maxResults": 10}}'
curl localhost:9000/gmail -H "Content-Type: application/json" -d '{"method": "messages.send", "params": {"to": "team@co.com", "subject": "Done", "body": "All green"}}'
curl localhost:9000/gmail -H "Content-Type: application/json" -d '{"method": "profile", "params": {}}'
```
- Recipient restrictions with glob patterns (allow `*@mycompany.com`, deny `*`)
- Read/write access levels
- Simple send interface: just pass `to`, `subject`, `body` — gateway builds the MIME message
- Supported: `messages.list/get/send/modify/trash`, `threads.list/get`, `labels.list/create`, `drafts.list/create`, `profile`

## YAML Manifest = Policy

Each project gets a manifest that defines exactly what the agent can do:

```yaml
project:
  name: my-project
  description: My awesome project

# AWS — multi-account with per-account permissions
aws:
  accounts:
    - account: "123456789012"
      region: us-east-1
      name: dev
      sso_role: AdministratorAccess
      services:
        s3: [GetObject, PutObject, ListBuckets]
        dynamodb: [Query, GetItem, PutItem]
        # Constrained: only specific CodeBuild projects
        codebuild:
          actions: [StartBuild, BatchGetBuilds]
          constraints:
            projectName: [pipeline-factory]

    - account: "987654321098"
      name: prod
      sso_role: ReadOnlyAccess
      services:
        s3: [GetObject, ListBuckets]  # read-only in prod

# Git — repo + branch restrictions
git:
  push: true
  repos:
    - name: my-org/my-repo
      branches:
        allow: ["feature/*", "fix/*"]
        deny: [main]

# Slack — channel restrictions
slack:
  access: readwrite
  actions: [chat.postMessage, conversations.list, conversations.history]
  channels:
    allow: ["#engineering", "#deploys", "#alerts-*"]
    deny: ["#executive"]

# Gmail — recipient restrictions
gmail:
  access: readwrite
  actions: [messages.list, messages.get, messages.send, profile]
  recipients:
    allow: ["*@mycompany.com"]
    # No deny needed — allow list acts as whitelist (anything not matching is denied)
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/aws` | POST | Proxy any AWS API call through policy check |
| `/git/clone` | POST | Clone/pull a repo into workspace |
| `/git/push` | POST | Push branch (with branch restrictions) |
| `/git/pr` | POST | Create Bitbucket PR (with optional merge watch) |
| `/git/create-repo` | POST | Create repo with branch protection |
| `/git/pr/status/{repo}/{id}` | GET | Check PR merge status |
| `/git/pr/watchers` | GET | List active PR watchers |
| `/slack` | POST | Proxy Slack API call through policy check |
| `/gmail` | POST | Proxy Gmail API call through policy check |
| `/whoami` | GET | Show current policy permissions |
| `/health` | GET | Health check (no auth required) |
| `/auth/status` | GET | Check AWS SSO status |
| `/auth/login` | POST | Start AWS SSO login |
| `/dashboard` | GET | Web UI — audit log, manifests, stats |
| `/api/logs` | GET | Query audit log |
| `/api/stats` | GET | Aggregate stats |
| `/api/manifests` | GET | List project manifests |
| `/api/manifest` | GET/POST/PUT | CRUD manifests |
| `/api/activate` | POST | Switch active project at runtime |
| `/api/hook-message` | GET | Get prompt-submit reminder text |

## Security

### Defense Layers

1. **YAML Policy** — whitelist of allowed services, actions, channels, recipients
2. **API Key Auth** — optional `YOLO_API_KEYS` env var, Bearer token on every request
3. **Input Validation** — path traversal protection, branch name validation, repo name sanitization
4. **Credential Isolation** — agent gets zero tokens/keys, gateway mounts host credentials read-only
5. **Audit Log** — every request logged with full bodies, timing, and allow/deny decision
6. **Sensitive Data Redaction** — credentials automatically stripped from audit log entries
7. **XSS Protection** — dashboard escapes all rendered data
8. **SQL Injection Prevention** — parameterized queries everywhere, whitelist on GROUP BY fields

### API Key Auth

Set `YOLO_API_KEYS` to require Bearer token authentication:

```bash
# .env
YOLO_API_KEYS=my-secret-key-1,my-secret-key-2

# Agent must include header
curl -H "Authorization: Bearer my-secret-key-1" localhost:9000/whoami
```

If `YOLO_API_KEYS` is empty, no auth required (localhost-only use).

## Environment Variables

```bash
# Gateway config
YOLO_PROJECT_MANIFEST    # Path to active manifest (or use /api/activate)
YOLO_API_KEYS            # Comma-separated API keys (optional)
YOLO_AUDIT_DB            # SQLite path (default: /data/audit.db)
YOLO_PROJECTS_DIR        # Manifests directory (default: /projects)
YOLO_WORKSPACE           # Git workspace (default: /workspace)

# AWS
AWS_CONFIG_FILE          # AWS config with SSO profiles

# Git
BITBUCKET_TOKEN          # Bitbucket app password
BITBUCKET_USERNAME       # Bitbucket username

# Slack
SLACK_BOT_TOKEN          # Slack bot token (xoxb-...)

# Gmail
GMAIL_ACCESS_TOKEN       # Gmail OAuth2 access token

# Notifications (optional)
TELEGRAM_BOT_TOKEN       # Telegram notifications
TELEGRAM_CHAT_ID         # Target chat
```

## Architecture

```
gateway/
├── main.py              # FastAPI app, audit middleware, dashboard, manifest CRUD
├── policy.py            # YAML manifest parser — check_aws, check_git, check_slack, check_gmail
├── auth.py              # AWS SSO manager (OIDC device flow, session caching)
├── audit.py             # SQLite audit log with sensitive data redaction
├── routes/
│   ├── aws.py           # POST /aws — proxy any AWS API call
│   ├── git.py           # Git clone/push/PR with branch restrictions
│   ├── slack.py         # POST /slack — proxy Slack API calls
│   └── gmail.py         # POST /gmail — proxy Gmail API calls
├── templates/
│   └── dashboard.html   # Real-time web dashboard
├── Dockerfile
├── entrypoint.sh
└── pyproject.toml
```

## Using with Claude Code

Run Claude Code with `--dangerously-skip-permissions` and point it at the gateway instead of giving it direct access. Add this to your CLAUDE.md or system prompt:

```bash
export GATEWAY_URL=http://localhost:9000

# AWS
curl -s $GATEWAY_URL/aws -H "Content-Type: application/json" \
  -d '{"service":"s3","action":"ListBuckets","params":{}}'

# Git push
curl -s $GATEWAY_URL/git/push -H "Content-Type: application/json" \
  -d '{"repo":"org/repo","branch":"feature/my-work"}'

# Slack
curl -s $GATEWAY_URL/slack -H "Content-Type: application/json" \
  -d '{"method":"chat.postMessage","params":{"channel":"#deploys","text":"Deployed!"}}'

# Gmail
curl -s $GATEWAY_URL/gmail -H "Content-Type: application/json" \
  -d '{"method":"messages.list","params":{"q":"is:unread","maxResults":5}}'

# Check permissions
curl -s $GATEWAY_URL/whoami
```

The `/api/hook-message` endpoint returns a reminder injected on every prompt via Claude Code hooks.

## Development

```bash
# Run locally without Docker
cd gateway
uv sync
uv run uvicorn gateway.main:app --host 0.0.0.0 --port 9000 --reload

# Set env vars
export YOLO_PROJECTS_DIR=../projects
export YOLO_AUDIT_DB=./audit.db
export YOLO_WORKSPACE=../workspace
export AWS_CONFIG_FILE=~/.aws/config
```

## Adding New Services

The gateway is designed to be extended. Each service follows the same pattern:

1. Create `gateway/routes/myservice.py` with a `router = APIRouter()`
2. Add `check_myservice()` to `gateway/policy.py`
3. Register in `gateway/main.py`: `app.include_router(myservice.router)`
4. Add policy section to manifest YAML
5. Update `_extract_action()` for audit log formatting

See `routes/slack.py` (83 lines) for a clean example.

## License

MIT
