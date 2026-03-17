import base64
import os
from email.mime.text import MIMEText

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

router = APIRouter()

# Gmail uses OAuth2 access token (from `gcloud auth application-default print-access-token`
# or a service account). Token is passed as env var and refreshed externally.
GMAIL_ACCESS_TOKEN = os.environ.get("GMAIL_ACCESS_TOKEN", "")
GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"

# Supported Gmail API methods (hardcoded safety layer)
SUPPORTED_METHODS = {
    # Read
    "messages.list",
    "messages.get",
    "labels.list",
    "threads.list",
    "threads.get",
    "drafts.list",
    "profile",
    # Write
    "messages.send",
    "messages.modify",
    "messages.trash",
    "drafts.create",
    "labels.create",
}

# Methods classified as write operations
_WRITE_METHODS = {"messages.send", "messages.modify", "messages.trash", "drafts.create", "labels.create"}
_READ_METHODS = SUPPORTED_METHODS - _WRITE_METHODS


class GmailRequest(BaseModel):
    method: str
    params: dict = {}


def _build_message(to: str, subject: str, body: str, cc: str = "", bcc: str = "") -> dict:
    """Build a Gmail API message payload from simple fields."""
    msg = MIMEText(body)
    msg["to"] = to
    msg["subject"] = subject
    if cc:
        msg["cc"] = cc
    if bcc:
        msg["bcc"] = bcc
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    return {"raw": raw}


@router.post("/gmail")
async def gmail_proxy(req: GmailRequest, request: Request):
    policy = request.state.policy

    if not GMAIL_ACCESS_TOKEN:
        raise HTTPException(500, "GMAIL_ACCESS_TOKEN not configured on gateway")

    if req.method not in SUPPORTED_METHODS:
        raise HTTPException(400, f"Unsupported Gmail method: {req.method}. Supported: {sorted(SUPPORTED_METHODS)}")

    # Extract recipient for policy check (only for send)
    recipient = ""
    if req.method == "messages.send":
        recipient = req.params.get("to", "")

    # Policy check
    result = policy.check_gmail(req.method, recipient=recipient)
    if not result.allowed:
        raise HTTPException(403, result.reason)

    # Build the API call
    headers = {"Authorization": f"Bearer {GMAIL_ACCESS_TOKEN}"}
    user_id = req.params.get("userId", "me")

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            if req.method == "messages.list":
                url = f"{GMAIL_API_BASE}/users/{user_id}/messages"
                query = {}
                if req.params.get("q"):
                    query["q"] = req.params["q"]
                if req.params.get("maxResults"):
                    query["maxResults"] = req.params["maxResults"]
                if req.params.get("labelIds"):
                    query["labelIds"] = req.params["labelIds"]
                if req.params.get("pageToken"):
                    query["pageToken"] = req.params["pageToken"]
                resp = await client.get(url, headers=headers, params=query)

            elif req.method == "messages.get":
                msg_id = req.params.get("id", "")
                if not msg_id:
                    raise HTTPException(400, "messages.get requires 'id' param")
                fmt = req.params.get("format", "metadata")
                url = f"{GMAIL_API_BASE}/users/{user_id}/messages/{msg_id}"
                resp = await client.get(url, headers=headers, params={"format": fmt})

            elif req.method == "messages.send":
                url = f"{GMAIL_API_BASE}/users/{user_id}/messages/send"
                # Support both raw message and simple fields
                if req.params.get("raw"):
                    body = {"raw": req.params["raw"]}
                else:
                    to = req.params.get("to", "")
                    subject = req.params.get("subject", "")
                    text = req.params.get("body", "")
                    cc = req.params.get("cc", "")
                    bcc = req.params.get("bcc", "")
                    if not to:
                        raise HTTPException(400, "messages.send requires 'to' param")
                    body = _build_message(to, subject, text, cc, bcc)
                resp = await client.post(url, headers=headers, json=body)

            elif req.method == "messages.modify":
                msg_id = req.params.get("id", "")
                if not msg_id:
                    raise HTTPException(400, "messages.modify requires 'id' param")
                url = f"{GMAIL_API_BASE}/users/{user_id}/messages/{msg_id}/modify"
                body = {}
                if req.params.get("addLabelIds"):
                    body["addLabelIds"] = req.params["addLabelIds"]
                if req.params.get("removeLabelIds"):
                    body["removeLabelIds"] = req.params["removeLabelIds"]
                resp = await client.post(url, headers=headers, json=body)

            elif req.method == "messages.trash":
                msg_id = req.params.get("id", "")
                if not msg_id:
                    raise HTTPException(400, "messages.trash requires 'id' param")
                url = f"{GMAIL_API_BASE}/users/{user_id}/messages/{msg_id}/trash"
                resp = await client.post(url, headers=headers)

            elif req.method == "labels.list":
                url = f"{GMAIL_API_BASE}/users/{user_id}/labels"
                resp = await client.get(url, headers=headers)

            elif req.method == "labels.create":
                url = f"{GMAIL_API_BASE}/users/{user_id}/labels"
                resp = await client.post(url, headers=headers, json={
                    "name": req.params.get("name", ""),
                    "labelListVisibility": req.params.get("labelListVisibility", "labelShow"),
                    "messageListVisibility": req.params.get("messageListVisibility", "show"),
                })

            elif req.method == "threads.list":
                url = f"{GMAIL_API_BASE}/users/{user_id}/threads"
                query = {}
                if req.params.get("q"):
                    query["q"] = req.params["q"]
                if req.params.get("maxResults"):
                    query["maxResults"] = req.params["maxResults"]
                if req.params.get("pageToken"):
                    query["pageToken"] = req.params["pageToken"]
                resp = await client.get(url, headers=headers, params=query)

            elif req.method == "threads.get":
                thread_id = req.params.get("id", "")
                if not thread_id:
                    raise HTTPException(400, "threads.get requires 'id' param")
                fmt = req.params.get("format", "metadata")
                url = f"{GMAIL_API_BASE}/users/{user_id}/threads/{thread_id}"
                resp = await client.get(url, headers=headers, params={"format": fmt})

            elif req.method == "drafts.list":
                url = f"{GMAIL_API_BASE}/users/{user_id}/drafts"
                resp = await client.get(url, headers=headers)

            elif req.method == "drafts.create":
                url = f"{GMAIL_API_BASE}/users/{user_id}/drafts"
                to = req.params.get("to", "")
                subject = req.params.get("subject", "")
                text = req.params.get("body", "")
                message = _build_message(to, subject, text)
                resp = await client.post(url, headers=headers, json={"message": message})

            elif req.method == "profile":
                url = f"{GMAIL_API_BASE}/users/{user_id}/profile"
                resp = await client.get(url, headers=headers)

            else:
                raise HTTPException(400, f"Method {req.method} not implemented")

    except HTTPException:
        raise
    except httpx.TimeoutException:
        raise HTTPException(504, "Gmail API timed out")
    except Exception as e:
        raise HTTPException(500, f"Gmail request failed: {e}")

    # Handle Gmail API errors
    if resp.status_code == 401:
        raise HTTPException(401, "Gmail token expired — refresh GMAIL_ACCESS_TOKEN")
    if resp.status_code >= 400:
        try:
            error_data = resp.json()
            error_msg = error_data.get("error", {}).get("message", resp.text[:200])
        except Exception:
            error_msg = resp.text[:200]
        raise HTTPException(resp.status_code, f"Gmail API error: {error_msg}")

    return resp.json()
