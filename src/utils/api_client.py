"""
Shared REST API client for interacting with vulnerable test targets (e.g. VAmPI).

Reads target configuration and test credentials from config/*.yaml rather than
hardcoding them in source, per project convention (see CLAUDE.md).

This module handles connection/auth mechanics only. It does not contain any
vulnerability test logic — that lives in src/vulnerabilities/.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

import requests
import yaml

logger = logging.getLogger(__name__)


class ConfigError(Exception):
    """Raised when the target config file is missing or malformed."""


class APIClient:
    """
    Thin wrapper around `requests` for a single REST target, driven by a
    YAML config file (e.g. config/vampi.yaml).

    Usage:
        client = APIClient.from_config("config/vampi.yaml")
        client.register("attacker")
        token = client.login("attacker")
        resp = client.get("/books/v1/some-title", as_user="attacker")
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        target = config.get("target", {})
        self.base_url: str = target["base_url"].rstrip("/")
        self.timeout: int = target.get("timeout_seconds", 10)
        self.endpoints: dict[str, str] = target.get("endpoints", {})

        auth_cfg = config.get("auth", {})
        self.token_header: str = auth_cfg.get("token_header", "Authorization")
        self.token_prefix: str = auth_cfg.get("token_prefix", "Bearer")

        self.test_users: dict[str, dict[str, str]] = config.get("test_users", {})

        # role name -> JWT/token string, populated after login()
        self._tokens: dict[str, str] = {}

        self.session = requests.Session()

    @classmethod
    def from_config(cls, config_path: str | Path) -> "APIClient":
        path = Path(config_path)
        if not path.exists():
            raise ConfigError(f"Config file not found: {path}")
        with path.open("r") as f:
            data = yaml.safe_load(f)
        if not data or "target" not in data:
            raise ConfigError(f"Config file missing required 'target' section: {path}")
        return cls(data)

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _headers_for(self, as_user: Optional[str]) -> dict[str, str]:
        headers = {}
        if as_user:
            token = self._tokens.get(as_user)
            if not token:
                raise RuntimeError(
                    f"No token stored for user role '{as_user}'. Call login() first."
                )
            headers[self.token_header] = f"{self.token_prefix} {token}"
        return headers

    def seed_database(self) -> requests.Response:
        """Hit the createdb endpoint to (re)populate dummy data."""
        path = self.endpoints.get("createdb", "/createdb")
        resp = self.session.get(self._url(path), timeout=self.timeout)
        logger.info("Seed DB: %s -> %s", path, resp.status_code)
        return resp

    def register(self, role: str) -> requests.Response:
        """Register a test user identified by role (e.g. 'attacker', 'victim')."""
        user = self._require_user(role)
        path = self.endpoints.get("register", "/users/v1/register")
        payload = {
            "username": user["username"],
            "password": user["password"],
            "email": user["email"],
        }
        resp = self.session.post(self._url(path), json=payload, timeout=self.timeout)
        logger.info("Register '%s': %s -> %s", role, path, resp.status_code)
        return resp

    def login(self, role: str) -> str:
        """Log in a test user and store their token for later requests."""
        user = self._require_user(role)
        path = self.endpoints.get("login", "/users/v1/login")
        payload = {"username": user["username"], "password": user["password"]}
        resp = self.session.post(self._url(path), json=payload, timeout=self.timeout)
        resp.raise_for_status()

        data = resp.json()
        token = data.get("auth_token")
        if not token:
            raise RuntimeError(f"Login response for '{role}' did not contain a token: {data}")

        self._tokens[role] = token
        logger.info("Login '%s': token stored", role)
        return token

    def get(self, path: str, as_user: Optional[str] = None, **kwargs: Any) -> requests.Response:
        return self.session.get(
            self._url(path), headers=self._headers_for(as_user), timeout=self.timeout, **kwargs
        )

    def post(self, path: str, as_user: Optional[str] = None, **kwargs: Any) -> requests.Response:
        return self.session.post(
            self._url(path), headers=self._headers_for(as_user), timeout=self.timeout, **kwargs
        )

    def put(self, path: str, as_user: Optional[str] = None, **kwargs: Any) -> requests.Response:
        return self.session.put(
            self._url(path), headers=self._headers_for(as_user), timeout=self.timeout, **kwargs
        )

    def delete(self, path: str, as_user: Optional[str] = None, **kwargs: Any) -> requests.Response:
        return self.session.delete(
            self._url(path), headers=self._headers_for(as_user), timeout=self.timeout, **kwargs
        )

    def _require_user(self, role: str) -> dict[str, str]:
        user = self.test_users.get(role)
        if not user:
            raise ConfigError(f"No test user configured for role '{role}' in config file")
        return user