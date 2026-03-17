import os

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

router = APIRouter()

SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN", "")
SLACK_API_BASE = "https://slack.com/api"

# Supported Slack API methods (hardcoded safety layer)
SUPPORTED_METHODS = {
    # Read
    "conversations.list",
    "conversations.history",
    "conversations.info",
    "users.list",
    "users.info",
    # Write
    "chat.postMessage",
    "chat.update",
    "reactions.add",
    "files.upload",
}

# Methods that take a channel param — used for channel restriction enforcement
_CHANNEL_PARAM = {
    "chat.postMessage": "channel",
    "chat.update": "channel",
    "conversations.history": "channel",
    "conversations.info": "channel",
    "reactions.add": "channel",
    "files.upload": "channels",
}


class SlackRequest(BaseModel):
    method: str
    params: dict = {}


@router.post("/slack")
async def slack_proxy(req: SlackRequest, request: Request):
    policy = request.state.policy

    if not SLACK_BOT_TOKEN:
        raise HTTPException(500, "SLACK_BOT_TOKEN not configured on gateway")

    # Validate method is one we support
    if req.method not in SUPPORTED_METHODS:
        raise HTTPException(400, f"Unsupported Slack method: {req.method}. Supported: {sorted(SUPPORTED_METHODS)}")

    # Extract channel for policy check (method-aware param name)
    channel_key = _CHANNEL_PARAM.get(req.method, "")
    channel = str(req.params.get(channel_key, "")) if channel_key else ""

    # Policy check
    result = policy.check_slack(req.method, channel=channel)
    if not result.allowed:
        raise HTTPException(403, result.reason)

    # Call Slack API
    url = f"{SLACK_API_BASE}/{req.method}"
    headers = {"Authorization": f"Bearer {SLACK_BOT_TOKEN}"}

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(url, headers=headers, json=req.params)
    except httpx.TimeoutException:
        raise HTTPException(504, "Slack API timed out")
    except Exception as e:
        raise HTTPException(500, f"Slack request failed: {e}")

    data = resp.json()

    # Slack always returns 200 with ok:true/false
    if not data.get("ok"):
        error = data.get("error", "unknown_error")
        status = 401 if error in ("not_authed", "invalid_auth", "account_inactive", "token_revoked") else 400
        raise HTTPException(status, f"Slack API error: {error}")

    return data
