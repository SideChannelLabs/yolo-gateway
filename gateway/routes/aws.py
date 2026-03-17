import re

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from ..auth import SSOLoginRequired

router = APIRouter()


class AWSRequest(BaseModel):
    service: str
    action: str
    params: dict = {}
    account: str = ""  # optional: target specific account


def _camel_to_snake(name: str) -> str:
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


@router.post("/aws")
async def aws_proxy(req: AWSRequest, request: Request):
    policy = request.state.policy
    aws_auth = request.state.aws_auth

    # Policy check (with optional account targeting + resource constraints)
    result = policy.check_aws(req.service, req.action, account_id=req.account, params=req.params)
    if not result.allowed:
        raise HTTPException(403, result.reason)

    # Get client — use specified account or default
    account_id = req.account or policy.get_aws_account()
    region = policy.get_aws_region(account_id)
    sso_role = policy.get_aws_sso_role(account_id)

    try:
        client = aws_auth.get_client(req.service, account_id, region, sso_role=sso_role)
    except SSOLoginRequired as e:
        raise HTTPException(401, {
            "error": "SSO session expired",
            "account": e.account_id,
            "profile": e.profile,
            "action": e.detail,
        })

    # Execute the AWS API call
    method_name = _camel_to_snake(req.action)
    method = getattr(client, method_name, None)
    if method is None:
        raise HTTPException(400, f"Unknown action '{req.action}' (method '{method_name}') on {req.service}")

    try:
        response = method(**req.params)
    except Exception as e:
        err = str(e)
        if "expired" in err.lower() or "token" in err.lower():
            raise HTTPException(401, {
                "error": "SSO session expired during call",
                "action": f"Run: aws sso login for account {account_id}",
            })
        raise HTTPException(500, f"AWS error: {err}")

    # Clean up response
    response.pop("ResponseMetadata", None)
    return response
