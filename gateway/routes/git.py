import asyncio
import os
import re
import subprocess
import time
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

router = APIRouter()

# Strict validation patterns — prevent path traversal and command injection
_SAFE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
_SAFE_BRANCH_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9./_-]*$")


def _validate_branch(branch: str):
    """Validate branch name. Raises HTTPException on invalid input."""
    if not _SAFE_BRANCH_RE.match(branch) or ".." in branch or branch.startswith("-"):
        raise HTTPException(400, f"Invalid branch name: {branch}")


# PR Watch System — tracks PRs waiting for merge
_pr_watchers: dict[str, dict] = {}
_pr_watcher_task: asyncio.Task | None = None

WORKSPACE_ROOT = os.environ.get("YOLO_WORKSPACE", "/workspace")


def _safe_repo_dir(repo: str) -> str:
    """Resolve repo name to a safe workspace path. Raises HTTPException on traversal attempts."""
    repo_name = repo.split("/")[-1]
    if not _SAFE_NAME_RE.match(repo_name) or ".." in repo_name:
        raise HTTPException(400, f"Invalid repository name: {repo_name}")
    dest = os.path.realpath(os.path.join(WORKSPACE_ROOT, repo_name))
    if not dest.startswith(os.path.realpath(WORKSPACE_ROOT)):
        raise HTTPException(400, "Repository path escapes workspace")
    return dest
BITBUCKET_TOKEN = os.environ.get("BITBUCKET_TOKEN", "")
BITBUCKET_USERNAME = os.environ.get("BITBUCKET_USERNAME", "")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
TELEGRAM_THREAD_ID = os.environ.get("TELEGRAM_THREAD_ID", "")


def auto_clone_repos(repos: list[dict], audit=None, project: str = "unknown"):
    """Clone all repos from the manifest into /workspace/ on startup."""
    for repo_cfg in repos:
        repo = repo_cfg.get("name", "")
        if not repo:
            continue
        repo_name = repo.split("/")[-1]
        if not _SAFE_NAME_RE.match(repo_name):
            print(f"  {repo_name}: SKIPPED — invalid name")
            continue
        dest = os.path.join(WORKSPACE_ROOT, repo_name)
        clone_url = _clone_url(repo)

        t0 = time.time()

        if os.path.exists(dest):
            print(f"  {repo_name}: already exists — pulling latest")
            _run_git(["fetch", "origin"], cwd=dest)
            r = _run_git(["pull", "--ff-only"], cwd=dest)
            elapsed = int((time.time() - t0) * 1000)
            if audit:
                from ..audit import AuditEntry
                audit.log(AuditEntry(
                    project=project,
                    decision="ALLOWED",
                    action=f"git:pull:{repo}",
                    request_method="STARTUP",
                    request_path="/git/auto-clone",
                    response_status=200 if r.returncode == 0 else 500,
                    response_time_ms=elapsed,
                    error_message=r.stderr.strip() if r.returncode != 0 else None,
                ))
        else:
            print(f"  {repo_name}: cloning...")
            r = _run_git(["clone", clone_url, dest])
            elapsed = int((time.time() - t0) * 1000)
            if r.returncode != 0:
                print(f"  {repo_name}: clone FAILED — {r.stderr.strip()}")
                if audit:
                    from ..audit import AuditEntry
                    audit.log(AuditEntry(
                        project=project,
                        decision="ERROR",
                        action=f"git:clone:{repo}",
                        request_method="STARTUP",
                        request_path="/git/auto-clone",
                        response_status=500,
                        response_time_ms=elapsed,
                        error_message=r.stderr.strip(),
                    ))
            else:
                print(f"  {repo_name}: cloned to /workspace/{repo_name}")
                if audit:
                    from ..audit import AuditEntry
                    audit.log(AuditEntry(
                        project=project,
                        decision="ALLOWED",
                        action=f"git:clone:{repo}",
                        request_method="STARTUP",
                        request_path="/git/auto-clone",
                        response_status=200,
                        response_time_ms=elapsed,
                    ))


def _clone_url(repo: str) -> str:
    """Build clone URL — SSH preferred, HTTPS token fallback."""
    return f"git@bitbucket.org:{repo}.git"


def _run_git(args: list[str], cwd: str | None = None) -> subprocess.CompletedProcess:
    """Run a git command and return result."""
    cmd = ["git"] + args
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=120)


class CloneRequest(BaseModel):
    repo: str
    branch: str = "main"


class PushRequest(BaseModel):
    repo: str
    branch: str


class PRRequest(BaseModel):
    repo: str
    source_branch: str
    destination_branch: str = "main"
    title: str
    description: str = ""
    watch: bool = False
    auto_pull: bool = True


class CreateRepoRequest(BaseModel):
    workspace: str
    repo: str
    description: str = ""
    is_private: bool = True


@router.post("/git/clone")
async def clone_repo(req: CloneRequest, request: Request):
    policy = request.state.policy

    result = policy.check_git_clone(req.repo)
    if not result.allowed:
        raise HTTPException(403, result.reason)

    _validate_branch(req.branch)
    dest = _safe_repo_dir(req.repo)
    repo_name = os.path.basename(dest)
    clone_url = _clone_url(req.repo)

    if os.path.exists(dest):
        r = _run_git(["fetch", "origin"], cwd=dest)
        if r.returncode != 0:
            raise HTTPException(500, f"git fetch failed: {r.stderr}")

        r = _run_git(["checkout", req.branch], cwd=dest)
        if r.returncode != 0:
            _run_git(["checkout", "-b", req.branch, f"origin/{req.branch}"], cwd=dest)

        r = _run_git(["pull", "origin", req.branch], cwd=dest)
        return {"status": "updated", "path": f"/workspace/{repo_name}", "branch": req.branch}
    else:
        r = _run_git(["clone", "-b", req.branch, clone_url, dest])
        if r.returncode != 0:
            raise HTTPException(500, f"git clone failed: {r.stderr}")

        return {"status": "cloned", "path": f"/workspace/{repo_name}", "branch": req.branch}


@router.post("/git/push")
async def push_repo(req: PushRequest, request: Request):
    policy = request.state.policy

    result = policy.check_git_push(req.repo, req.branch)
    if not result.allowed:
        raise HTTPException(403, result.reason)

    _validate_branch(req.branch)
    repo_dir = _safe_repo_dir(req.repo)
    repo_name = os.path.basename(repo_dir)

    if not os.path.exists(repo_dir):
        raise HTTPException(400, f"Repo not cloned at /workspace/{repo_name}")

    clone_url = _clone_url(req.repo)
    _run_git(["remote", "set-url", "origin", clone_url], cwd=repo_dir)

    r = _run_git(["push", "-u", "origin", req.branch], cwd=repo_dir)
    if r.returncode != 0:
        raise HTTPException(500, f"git push failed: {r.stderr}")

    return {"status": "pushed", "repo": req.repo, "branch": req.branch, "output": r.stdout}


async def _notify_telegram(text: str):
    """Send notification to Telegram (if configured)."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            payload = {
                "chat_id": TELEGRAM_CHAT_ID,
                "text": text,
                "parse_mode": "HTML",
            }
            if TELEGRAM_THREAD_ID:
                payload["message_thread_id"] = int(TELEGRAM_THREAD_ID)
            await client.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json=payload,
            )
    except Exception:
        pass


@router.post("/git/pr")
async def create_pr(req: PRRequest, request: Request):
    policy = request.state.policy

    result = policy.check_git_clone(req.repo)
    if not result.allowed:
        raise HTTPException(403, result.reason)

    if not BITBUCKET_TOKEN:
        raise HTTPException(500, "BITBUCKET_TOKEN not configured on gateway")

    url = f"https://api.bitbucket.org/2.0/repositories/{req.repo}/pullrequests"
    payload = {
        "title": req.title,
        "description": req.description,
        "source": {"branch": {"name": req.source_branch}},
        "destination": {"branch": {"name": req.destination_branch}},
        "close_source_branch": False,
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            url,
            json=payload,
            auth=(BITBUCKET_USERNAME or "x-token-auth", BITBUCKET_TOKEN),
            timeout=30,
        )

    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, f"Bitbucket API error: {resp.text}")

    data = resp.json()
    pr_id = data.get("id")
    pr_url = data.get("links", {}).get("html", {}).get("href", "")

    # Notify Telegram
    await _notify_telegram(
        f"\U0001f4e6 <b>New PR #{pr_id}</b>\n<b>{req.title}</b>\nRepo: <code>{req.repo}</code>\n"
        f"<a href=\"{pr_url}\">View PR</a>"
    )

    result = {
        "status": "created",
        "pr_id": pr_id,
        "url": pr_url,
        "title": req.title,
    }

    # Auto-watch for merge if requested
    if req.watch and pr_id:
        global _pr_watcher_task
        key = f"{req.repo}/{pr_id}"
        _pr_watchers[key] = {
            "repo": req.repo,
            "pr_id": pr_id,
            "auto_pull": req.auto_pull,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "checks": 0,
            "last_check": "",
            "state": "OPEN",
        }
        if _pr_watcher_task is None or _pr_watcher_task.done():
            _pr_watcher_task = asyncio.create_task(_pr_watch_loop())
        result["watching"] = True
        result["poll_url"] = f"/git/pr/status/{req.repo}/{pr_id}"

    return result


@router.post("/git/create-repo")
async def create_repo_endpoint(req: CreateRepoRequest, request: Request):
    """Create a Bitbucket repository with branch protection on main."""
    policy = request.state.policy
    full_name = f"{req.workspace}/{req.repo}"

    result = policy.check_git_clone(full_name)
    if not result.allowed:
        raise HTTPException(403, result.reason)

    if not BITBUCKET_TOKEN:
        raise HTTPException(500, "BITBUCKET_TOKEN not configured on gateway")

    auth = (BITBUCKET_USERNAME or "x-token-auth", BITBUCKET_TOKEN)

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"https://api.bitbucket.org/2.0/repositories/{full_name}",
            json={"scm": "git", "is_private": req.is_private, "description": req.description},
            auth=auth,
            timeout=30,
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, f"Bitbucket API error: {resp.text}")

        repo_data = resp.json()

        # Set branch protection
        restrictions_url = f"https://api.bitbucket.org/2.0/repositories/{full_name}/branch-restrictions"
        await client.post(
            restrictions_url,
            json={"kind": "push", "pattern": "main", "users": [], "groups": []},
            auth=auth, timeout=30,
        )
        await client.post(
            restrictions_url,
            json={"kind": "require_approvals_to_merge", "pattern": "main", "value": 1},
            auth=auth, timeout=30,
        )

    return {
        "status": "created",
        "full_name": repo_data.get("full_name"),
        "url": repo_data.get("links", {}).get("html", {}).get("href", ""),
        "branch_protection": "configured",
    }


# ═══ PR Watch ═══

class PRWatchRequest(BaseModel):
    repo: str
    pr_id: int
    auto_pull: bool = True


async def _check_pr_status(repo: str, pr_id: int) -> dict:
    if not BITBUCKET_TOKEN:
        return {"error": "BITBUCKET_TOKEN not configured"}

    url = f"https://api.bitbucket.org/2.0/repositories/{repo}/pullrequests/{pr_id}"
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(url, auth=(BITBUCKET_USERNAME or "x-token-auth", BITBUCKET_TOKEN))
    if resp.status_code >= 400:
        return {"error": f"Bitbucket API {resp.status_code}: {resp.text[:200]}"}

    data = resp.json()
    return {
        "pr_id": pr_id,
        "repo": repo,
        "state": data.get("state", "UNKNOWN"),
        "title": data.get("title", ""),
        "source_branch": data.get("source", {}).get("branch", {}).get("name", ""),
        "destination_branch": data.get("destination", {}).get("branch", {}).get("name", ""),
        "merge_commit": data.get("merge_commit", {}).get("hash", "") if data.get("merge_commit") else "",
        "url": data.get("links", {}).get("html", {}).get("href", ""),
        "updated_on": data.get("updated_on", ""),
    }


@router.get("/git/pr/status/{repo:path}/{pr_id}")
async def get_pr_status(repo: str, pr_id: int):
    result = await _check_pr_status(repo, pr_id)
    if "error" in result:
        raise HTTPException(500, result["error"])
    key = f"{repo}/{pr_id}"
    result["watched"] = key in _pr_watchers
    if result["watched"]:
        w = _pr_watchers[key]
        result["watch_started"] = w["started_at"]
        result["checks"] = w["checks"]
    return result


@router.post("/git/pr/watch")
async def watch_pr(req: PRWatchRequest):
    global _pr_watcher_task
    key = f"{req.repo}/{req.pr_id}"

    status = await _check_pr_status(req.repo, req.pr_id)
    if "error" in status:
        raise HTTPException(500, status["error"])

    if status["state"] == "MERGED":
        if req.auto_pull:
            _auto_pull_repo(req.repo)
        return {"status": "already_merged", "pr_id": req.pr_id, "repo": req.repo}

    if status["state"] in ("DECLINED", "SUPERSEDED"):
        return {"status": status["state"].lower(), "pr_id": req.pr_id, "repo": req.repo}

    _pr_watchers[key] = {
        "repo": req.repo,
        "pr_id": req.pr_id,
        "auto_pull": req.auto_pull,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "checks": 0,
        "last_check": "",
        "state": "OPEN",
    }

    if _pr_watcher_task is None or _pr_watcher_task.done():
        _pr_watcher_task = asyncio.create_task(_pr_watch_loop())

    return {
        "status": "watching",
        "pr_id": req.pr_id,
        "repo": req.repo,
        "message": f"Watching PR #{req.pr_id}. Poll GET /git/pr/status/{req.repo}/{req.pr_id} to check.",
    }


@router.get("/git/pr/watchers")
async def list_pr_watchers():
    return [{**w, "key": k} for k, w in _pr_watchers.items()]


@router.delete("/git/pr/watch/{repo:path}/{pr_id}")
async def stop_watching_pr(repo: str, pr_id: int):
    key = f"{repo}/{pr_id}"
    if key in _pr_watchers:
        del _pr_watchers[key]
        return {"status": "removed", "key": key}
    return {"status": "not_found", "key": key}


def _auto_pull_repo(repo: str):
    repo_name = repo.split("/")[-1]
    if not _SAFE_NAME_RE.match(repo_name):
        return
    dest = os.path.realpath(os.path.join(WORKSPACE_ROOT, repo_name))
    if not dest.startswith(os.path.realpath(WORKSPACE_ROOT)):
        return
    if not os.path.exists(dest):
        return
    _run_git(["checkout", "main"], cwd=dest)
    _run_git(["pull", "origin", "main"], cwd=dest)


async def _pr_watch_loop():
    """Background loop — polls watched PRs every 30s until all resolved."""
    while _pr_watchers:
        await asyncio.sleep(30)
        for key, w in list(_pr_watchers.items()):
            try:
                status = await _check_pr_status(w["repo"], w["pr_id"])
                w["checks"] += 1
                w["last_check"] = datetime.now(timezone.utc).isoformat()

                if "error" in status:
                    continue

                w["state"] = status["state"]

                if status["state"] == "MERGED":
                    if w["auto_pull"]:
                        await asyncio.to_thread(_auto_pull_repo, w["repo"])
                    w["merged_at"] = datetime.now(timezone.utc).isoformat()
                    w["merge_commit"] = status.get("merge_commit", "")
                    asyncio.create_task(_cleanup_watcher(key, delay=300))

                elif status["state"] in ("DECLINED", "SUPERSEDED"):
                    asyncio.create_task(_cleanup_watcher(key, delay=300))

            except Exception as e:
                print(f"  PR Watch: exception checking {key}: {e}")


async def _cleanup_watcher(key: str, delay: int = 300):
    await asyncio.sleep(delay)
    _pr_watchers.pop(key, None)
