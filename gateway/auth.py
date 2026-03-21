import configparser
import hashlib
import json
import os
import threading
import time

import boto3


class SSOLoginRequired(Exception):
    def __init__(self, profile: str, account_id: str, detail: str = ""):
        self.profile = profile
        self.account_id = account_id
        self.detail = detail
        super().__init__(f"SSO expired for {profile} (account {account_id}): {detail}")


class AWSAuthManager:
    def __init__(self, aws_config_path: str = "/root/.aws/config"):
        self._config_path = aws_config_path
        self._session_cache: dict = {}
        self._profile_map: dict = {}  # account_id -> profile_name
        self._sso_config: dict = {}   # profile -> {start_url, region, account_id, role_name}
        self._login_state: dict = {}  # account_id -> {status, url, ...}
        self._status_cache: dict = {}  # account_id -> {result, ts}
        self._status_cache_ttl = 30   # seconds

    def _build_profile_map(self):
        """Scan ~/.aws/config to map account IDs to profile names and SSO config."""
        config = configparser.ConfigParser()
        config.read(self._config_path)
        self._profile_map = {}
        self._sso_config = {}

        for section in config.sections():
            account_id = config.get(section, "sso_account_id", fallback="")
            if account_id:
                profile_name = section.replace("profile ", "")
                self._profile_map[account_id] = profile_name
                self._sso_config[profile_name] = {
                    "start_url": config.get(section, "sso_start_url", fallback=""),
                    "region": config.get(section, "sso_region", fallback="us-east-1"),
                    "account_id": account_id,
                    "role_name": config.get(section, "sso_role_name", fallback=""),
                }

    def _find_profile(self, account_id: str, sso_role: str = "") -> str:
        """Find the SSO profile for an AWS account ID, optionally matching a specific role."""
        if not self._profile_map:
            self._build_profile_map()

        if account_id not in self._profile_map:
            self._build_profile_map()

        if account_id not in self._profile_map:
            raise SSOLoginRequired(
                profile="(none)",
                account_id=account_id,
                detail=f"No SSO profile found for account {account_id}. "
                f"Configure SSO on host: aws configure sso --profile <name>",
            )

        # If a specific role is requested, find the profile that matches both account + role
        if sso_role:
            for profile, cfg in self._sso_config.items():
                if cfg.get("account_id") == account_id and cfg.get("role_name") == sso_role:
                    return profile
            # No exact match — fall back to account-only match but warn
            print(f"  WARNING: No profile found with role '{sso_role}' for account {account_id}, "
                  f"using default profile '{self._profile_map[account_id]}'")

        return self._profile_map[account_id]

    def _sso_cache_path(self, start_url: str) -> str:
        """Get the SSO token cache file path (same format as AWS CLI)."""
        cache_key = hashlib.sha1(start_url.encode("utf-8")).hexdigest()
        cache_dir = os.path.join(os.path.dirname(self._config_path), "sso", "cache")
        os.makedirs(cache_dir, exist_ok=True)
        return os.path.join(cache_dir, f"{cache_key}.json")

    def start_sso_login(self, account_id: str, sso_role: str = "") -> dict:
        """Initiate SSO OIDC device authorization flow."""
        profile = self._find_profile(account_id, sso_role=sso_role)
        sso_cfg = self._sso_config.get(profile, {})

        if not sso_cfg.get("start_url"):
            return {"status": "error", "error": f"No SSO start_url for profile {profile}"}

        # Check if already logging in
        existing = self._login_state.get(account_id, {})
        if existing.get("status") == "pending":
            return existing

        sso_region = sso_cfg["region"]
        start_url = sso_cfg["start_url"]

        try:
            oidc = boto3.client("sso-oidc", region_name=sso_region)

            # Register client
            client_reg = oidc.register_client(
                clientName="yolomode-gateway",
                clientType="public",
            )

            # Start device authorization
            device_auth = oidc.start_device_authorization(
                clientId=client_reg["clientId"],
                clientSecret=client_reg["clientSecret"],
                startUrl=start_url,
            )

            state = {
                "status": "pending",
                "account_id": account_id,
                "profile": profile,
                "verification_url": device_auth["verificationUriComplete"],
                "user_code": device_auth.get("userCode", ""),
                "device_code": device_auth["deviceCode"],
                "client_id": client_reg["clientId"],
                "client_secret": client_reg["clientSecret"],
                "start_url": start_url,
                "sso_region": sso_region,
                "interval": device_auth.get("interval", 5),
                "expires_at": time.time() + device_auth.get("expiresIn", 600),
            }
            self._login_state[account_id] = state

            # Start background polling
            thread = threading.Thread(
                target=self._poll_sso_token,
                args=(account_id,),
                daemon=True,
            )
            thread.start()

            return {
                "status": "pending",
                "verification_url": state["verification_url"],
                "user_code": state["user_code"],
                "message": f"Open this URL in your browser to authenticate: {state['verification_url']}",
            }

        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _poll_sso_token(self, account_id: str):
        """Background poll for SSO token after user authorizes."""
        state = self._login_state.get(account_id)
        if not state:
            return

        oidc = boto3.client("sso-oidc", region_name=state["sso_region"])
        interval = state["interval"]

        while time.time() < state["expires_at"]:
            time.sleep(interval)
            try:
                token_response = oidc.create_token(
                    clientId=state["client_id"],
                    clientSecret=state["client_secret"],
                    grantType="urn:ietf:params:oauth:grant-type:device_code",
                    deviceCode=state["device_code"],
                )

                # Write token to SSO cache (same format as AWS CLI)
                cache_path = self._sso_cache_path(state["start_url"])
                expiry = time.time() + token_response.get("expiresIn", 28800)
                cache_data = {
                    "startUrl": state["start_url"],
                    "region": state["sso_region"],
                    "accessToken": token_response["accessToken"],
                    "expiresAt": time.strftime(
                        "%Y-%m-%dT%H:%M:%SUTC", time.gmtime(expiry)
                    ),
                }
                with open(cache_path, "w") as f:
                    json.dump(cache_data, f)

                # Clear session cache so next boto3 call picks up new token
                self._session_cache.clear()

                self._login_state[account_id] = {
                    "status": "active",
                    "account_id": account_id,
                    "profile": state["profile"],
                    "message": "SSO login successful",
                }
                return

            except oidc.exceptions.AuthorizationPendingException:
                continue
            except oidc.exceptions.SlowDownException:
                interval += 2
                continue
            except oidc.exceptions.ExpiredTokenException:
                break
            except Exception as e:
                self._login_state[account_id] = {
                    "status": "error",
                    "error": str(e),
                }
                return

        self._login_state[account_id] = {
            "status": "expired",
            "error": "SSO login timed out — user did not authorize in time",
        }

    def get_login_state(self, account_id: str) -> dict:
        """Get current SSO login state for an account."""
        return self._login_state.get(account_id, {"status": "not_started"})

    def get_client(self, service: str, account_id: str, region: str = "us-east-1", sso_role: str = ""):
        """Get a boto3 client for a service, auto-resolving account ID to profile."""
        profile = self._find_profile(account_id, sso_role=sso_role)

        cache_key = f"{profile}:{service}:{region}"
        cached = self._session_cache.get(cache_key)
        if cached and cached["expires"] > time.time():
            return cached["client"]

        try:
            session = boto3.Session(profile_name=profile)
            client = session.client(service, region_name=region)

            if service == "sts":
                client.get_caller_identity()

            self._session_cache[cache_key] = {
                "client": client,
                "expires": time.time() + 2400,  # cache 40 min
            }
            return client

        except Exception as e:
            err = str(e)
            if "expired" in err.lower() or "token" in err.lower() or "sso" in err.lower():
                raise SSOLoginRequired(
                    profile=profile,
                    account_id=account_id,
                    detail="SSO session expired. Use /auth/login to re-authenticate.",
                )
            raise

    def check_account(self, account_id: str, sso_role: str = "") -> dict:
        """Check if we have a valid session for an account. Results cached for 30s."""
        # Return cached result if fresh
        cache_key = f"{account_id}:{sso_role}"
        cached = self._status_cache.get(cache_key)
        if cached and (time.time() - cached["ts"]) < self._status_cache_ttl:
            return cached["result"]

        # If login is in progress, report that (no cache)
        login_state = self._login_state.get(account_id, {})
        if login_state.get("status") == "pending":
            return {
                "status": "logging_in",
                "account": account_id,
                "verification_url": login_state.get("verification_url"),
                "message": "SSO login in progress — waiting for browser authorization",
            }

        try:
            profile = self._find_profile(account_id, sso_role=sso_role)
            session = boto3.Session(profile_name=profile)
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            result = {
                "status": "active",
                "account": identity["Account"],
                "arn": identity["Arn"],
                "profile": profile,
            }
        except SSOLoginRequired as e:
            result = {
                "status": "no_profile",
                "account": account_id,
                "error": e.detail,
            }
        except Exception:
            profile = self._profile_map.get(account_id, "unknown")
            result = {
                "status": "expired",
                "account": account_id,
                "profile": profile,
                "action": "Call /auth/login to authenticate",
            }

        self._status_cache[cache_key] = {"result": result, "ts": time.time()}
        return result
