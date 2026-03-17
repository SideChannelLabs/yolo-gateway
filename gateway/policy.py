import fnmatch
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass
class PolicyResult:
    allowed: bool
    reason: str


class PolicyEngine:
    def __init__(self, manifest_path: str | None = None):
        self._manifest_path = manifest_path
        if manifest_path and Path(manifest_path).exists():
            self._policy = self._load(manifest_path)
        else:
            self._policy = {}

    def _load(self, path: str) -> dict:
        with open(path) as f:
            return yaml.safe_load(f)

    def reload(self):
        if self._manifest_path and Path(self._manifest_path).exists():
            self._policy = self._load(self._manifest_path)

    def set_active_project(self, manifest_path: str):
        """Switch the active project manifest."""
        self._manifest_path = manifest_path
        self._policy = self._load(manifest_path)

    @property
    def has_project(self) -> bool:
        return bool(self._policy.get("project"))

    @property
    def project_name(self) -> str:
        return self._policy.get("project", {}).get("name", "unknown")

    @property
    def project_description(self) -> str:
        return self._policy.get("project", {}).get("description", "")

    # ══════════════════════════════════════════
    # AWS — supports both single and multi-account formats
    # ══════════════════════════════════════════

    def _get_aws_accounts(self) -> list[dict]:
        """Return list of AWS account configs, handling both old and new format."""
        aws = self._policy.get("aws", {})
        # New format: aws.accounts list
        if "accounts" in aws:
            return aws["accounts"]
        # Old format: single account at top level
        if "account" in aws:
            return [aws]
        return []

    def _get_aws_account_config(self, account_id: str = "") -> dict:
        """Get config for a specific account, or the first/default one."""
        accounts = self._get_aws_accounts()
        if not accounts:
            return {}
        if account_id:
            for a in accounts:
                if a.get("account") == account_id:
                    return a
            return {}
        return accounts[0]

    def get_aws_account(self) -> str:
        """Get default (first) AWS account ID."""
        cfg = self._get_aws_account_config()
        return cfg.get("account", "")

    def get_aws_region(self, account_id: str = "") -> str:
        cfg = self._get_aws_account_config(account_id)
        return cfg.get("region", "us-east-1")

    def get_aws_sso_role(self, account_id: str = "") -> str:
        cfg = self._get_aws_account_config(account_id)
        return cfg.get("sso_role", "")

    def get_aws_accounts(self) -> list[dict]:
        """Return all configured AWS accounts."""
        return self._get_aws_accounts()

    def get_git_repos(self) -> list[dict]:
        """Return list of repo configs from manifest."""
        return self._policy.get("git", {}).get("repos", [])

    def _parse_service_config(self, service_config) -> tuple[list, dict]:
        """Parse service config into (allowed_actions, constraints).

        Supports two formats:
          Simple:      s3: [GetObject, PutObject]
          Constrained: codebuild: { actions: [StartBuild], constraints: { projectName: [pipeline-factory] } }
        """
        if isinstance(service_config, list):
            return service_config, {}
        if isinstance(service_config, dict):
            return service_config.get("actions", []), service_config.get("constraints", {})
        return [], {}

    def check_aws(self, service: str, action: str, account_id: str = "", params: dict | None = None) -> PolicyResult:
        cfg = self._get_aws_account_config(account_id)
        if not cfg:
            if account_id:
                return PolicyResult(False, f"Account '{account_id}' not configured")
            return PolicyResult(False, f"No AWS accounts configured for {self.project_name}")

        services = cfg.get("services", {})
        if service not in services:
            return PolicyResult(False, f"Service '{service}' not allowed on account {cfg.get('account', '?')}")

        allowed_actions, constraints = self._parse_service_config(services[service])

        # Check action
        if "*" not in allowed_actions and action not in allowed_actions:
            return PolicyResult(False, f"Action '{action}' not allowed on {service}")

        # Check resource constraints
        if constraints:
            for param_name, allowed_values in constraints.items():
                actual = (params or {}).get(param_name, "")
                if not actual:
                    return PolicyResult(
                        False,
                        f"Resource constraint: {param_name} is required (allowed: {allowed_values})",
                    )
                if actual not in allowed_values:
                    return PolicyResult(
                        False,
                        f"Resource constraint: {param_name}='{actual}' not in allowed values {allowed_values}",
                    )

        return PolicyResult(True, "Allowed by policy")

    def check_git_clone(self, repo: str) -> PolicyResult:
        git = self._policy.get("git", {})
        repos = git.get("repos", [])

        for r in repos:
            name = r if isinstance(r, str) else r.get("name", "")
            if name == repo:
                return PolicyResult(True, "Repo access allowed")

        return PolicyResult(False, f"No access to repo '{repo}'")

    def check_git_push(self, repo: str, branch: str) -> PolicyResult:
        git = self._policy.get("git", {})

        if not git.get("push", False):
            return PolicyResult(False, "Push not allowed for this project")

        repos = git.get("repos", [])
        repo_config = None
        for r in repos:
            if isinstance(r, str):
                if r == repo:
                    repo_config = {}
                    break
            elif r.get("name") == repo:
                repo_config = r
                break

        if repo_config is None:
            return PolicyResult(False, f"No access to repo '{repo}'")

        branches = repo_config.get("branches", {})

        # Check deny list first
        deny = branches.get("deny", [])
        for pattern in deny:
            if fnmatch.fnmatch(branch, pattern) or branch == pattern:
                return PolicyResult(False, f"Push to '{branch}' is denied")

        # Check allow list
        allow = branches.get("allow", [])
        if allow:
            for pattern in allow:
                if fnmatch.fnmatch(branch, pattern):
                    return PolicyResult(True, f"Branch matches allowed pattern '{pattern}'")
            return PolicyResult(False, f"Branch '{branch}' doesn't match any allowed pattern")

        return PolicyResult(True, "Push allowed (no branch restrictions)")

    # ══════════════════════════════════════════
    # Slack
    # ══════════════════════════════════════════

    _SLACK_READ_METHODS = {
        "conversations.list", "conversations.history", "conversations.info",
        "users.list", "users.info",
    }
    _SLACK_WRITE_METHODS = {
        "chat.postMessage", "chat.update", "reactions.add", "files.upload",
    }

    def check_slack(self, method: str, channel: str = "") -> PolicyResult:
        slack = self._policy.get("slack", {})
        if not slack:
            return PolicyResult(False, "No Slack access configured for this project")

        # Check access level shortcut (read/write/readwrite)
        access = slack.get("access", "readwrite")
        if access == "read" and method in self._SLACK_WRITE_METHODS:
            return PolicyResult(False, f"Slack access is read-only — '{method}' is a write method")
        if access == "write" and method in self._SLACK_READ_METHODS:
            return PolicyResult(False, f"Slack access is write-only — '{method}' is a read method")

        # Check allowed actions
        actions = slack.get("actions", [])
        if actions and "*" not in actions and method not in actions:
            return PolicyResult(False, f"Slack method '{method}' not allowed")

        # Check channel restrictions (if channel provided and restrictions defined)
        if channel:
            channels = slack.get("channels", {})

            # Check deny first
            deny = channels.get("deny", [])
            for pattern in deny:
                if fnmatch.fnmatch(channel, pattern) or channel == pattern:
                    return PolicyResult(False, f"Slack channel '{channel}' is denied")

            # Check allow
            allow = channels.get("allow", [])
            if allow:
                for pattern in allow:
                    if fnmatch.fnmatch(channel, pattern) or channel == pattern:
                        return PolicyResult(True, f"Channel matches allowed pattern '{pattern}'")
                return PolicyResult(False, f"Slack channel '{channel}' doesn't match any allowed pattern")

        return PolicyResult(True, "Allowed by policy")

    # ══════════════════════════════════════════
    # Gmail
    # ══════════════════════════════════════════

    _GMAIL_READ_METHODS = {
        "messages.list", "messages.get", "labels.list",
        "threads.list", "threads.get", "drafts.list", "profile",
    }
    _GMAIL_WRITE_METHODS = {
        "messages.send", "messages.modify", "messages.trash",
        "drafts.create", "labels.create",
    }

    def check_gmail(self, method: str, recipient: str = "") -> PolicyResult:
        gmail = self._policy.get("gmail", {})
        if not gmail:
            return PolicyResult(False, "No Gmail access configured for this project")

        # Check access level shortcut
        access = gmail.get("access", "readwrite")
        if access == "read" and method in self._GMAIL_WRITE_METHODS:
            return PolicyResult(False, f"Gmail access is read-only — '{method}' is a write method")
        if access == "write" and method in self._GMAIL_READ_METHODS:
            return PolicyResult(False, f"Gmail access is write-only — '{method}' is a read method")

        # Check allowed actions
        actions = gmail.get("actions", [])
        if actions and "*" not in actions and method not in actions:
            return PolicyResult(False, f"Gmail method '{method}' not allowed")

        # Check recipient restrictions (only for send/draft)
        if recipient and method in ("messages.send", "drafts.create"):
            recipients = gmail.get("recipients", {})

            # Check deny first
            deny = recipients.get("deny", [])
            for pattern in deny:
                if fnmatch.fnmatch(recipient, pattern) or recipient == pattern:
                    return PolicyResult(False, f"Sending to '{recipient}' is denied")

            # Check allow
            allow = recipients.get("allow", [])
            if allow:
                for pattern in allow:
                    if fnmatch.fnmatch(recipient, pattern) or recipient == pattern:
                        return PolicyResult(True, f"Recipient matches allowed pattern '{pattern}'")
                return PolicyResult(False, f"Recipient '{recipient}' doesn't match any allowed pattern")

        return PolicyResult(True, "Allowed by policy")

    # ══════════════════════════════════════════
    # Permissions summary
    # ══════════════════════════════════════════

    def describe_permissions(self) -> dict:
        git = self._policy.get("git", {})

        result = {
            "project": self.project_name,
            "description": self.project_description,
            "aws": {"accounts": self._get_aws_accounts()},
            "git": {
                "push": git.get("push", False),
                "repos": git.get("repos", []),
            },
        }

        # Include Slack permissions if configured
        slack = self._policy.get("slack", {})
        if slack:
            result["slack"] = {
                "access": slack.get("access", "readwrite"),
                "actions": slack.get("actions", []),
                "channels": slack.get("channels", {}),
            }

        # Include Gmail permissions if configured
        gmail = self._policy.get("gmail", {})
        if gmail:
            result["gmail"] = {
                "access": gmail.get("access", "readwrite"),
                "actions": gmail.get("actions", []),
                "recipients": gmail.get("recipients", {}),
            }

        # Include claude_md if present
        claude_md = self._policy.get("claude_md", "")
        if claude_md and claude_md.strip():
            result["claude_md"] = claude_md

        return result
