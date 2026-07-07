"""
VAmPI-specific REST API client.

Extends RESTAPIClient with VAmPI's exact auth flow and endpoint shapes:
register/login payloads of {username, password, email}, the auth_token
field name in login responses, and the /createdb reseed endpoint.
"""

from __future__ import annotations

import logging
from typing import Any

import requests

from src.utils.api_client import ConfigError, RESTAPIClient

logger = logging.getLogger(__name__)


class VAmPIClient(RESTAPIClient):
    """RESTAPIClient subclass wired to VAmPI's auth flow and reseed endpoint."""

    @property
    def scan_config(self) -> dict[str, Any]:
        """The config file's `scan:` section (e.g. sqli_payloads) — RESTAPIClient
        only parses `target`/`auth`/`test_users`, so vulnerability modules that
        need config-driven scan scope read it through here rather than
        reaching into the client's private config dict directly."""
        return self._config.get("scan", {})

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

    def _require_user(self, role: str) -> dict[str, str]:
        user = self.test_users.get(role)
        if not user:
            raise ConfigError(f"No test user configured for role '{role}' in config file")
        return user
