from __future__ import annotations

import logging
from typing import Any

import requests

from src.utils.api_client import ConfigError, RESTAPIClient

logger = logging.getLogger(__name__)


class JuiceShopClient(RESTAPIClient):
    """RESTAPIClient for Juice Shop's auth flow and basket IDs."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._basket_ids: dict[str, int] = {}

    @property
    def scan_config(self) -> dict[str, Any]:
        return self._config.get("scan", {})

    def register(self, role: str) -> requests.Response:
        """Register a test user identified by role."""
        user = self._require_user(role)
        path = self.endpoints.get("register", "/api/Users/")
        payload = {
            "email": user["email"],
            "password": user["password"],
            "passwordRepeat": user["password"],
        }
        resp = self.session.post(self._url(path), json=payload, timeout=self.timeout)
        logger.info("Register '%s': %s -> %s", role, path, resp.status_code)
        return resp

    def login(self, role: str) -> str:
        """Log in a test user and store their auth token for later requests."""
        user = self._require_user(role)
        path = self.endpoints.get("login", "/rest/user/login")
        payload = {"email": user["email"], "password": user["password"]}
        resp = self.session.post(self._url(path), json=payload, timeout=self.timeout)
        resp.raise_for_status()

        data = resp.json()
        auth = data.get("authentication", {})
        token = auth.get("token")
        if not token:
            raise RuntimeError(
                f"Login response for '{role}' did not contain a token: {data}"
            )

        self._tokens[role] = token
        bid = auth.get("bid")
        if bid is not None:
            self._basket_ids[role] = bid
        logger.info("Login '%s': token stored, bid=%s", role, bid)
        return token

    def basket_id_for(self, role: str) -> int:
        """Retrieve basket id from `role`'s login response."""
        bid = self._basket_ids.get(role)
        if bid is None:
            raise RuntimeError(
                f"No basket id stored for user role '{role}'. Call login() first."
            )
        return bid

    def get_basket(self, basket_id: int, as_user: str | None) -> requests.Response:
        """
        GET a shopping basket by its raw (numeric)id which is 
        the object under test for the BOLA finding.

        e.g. Guessing the id by increaseing by 1 at a time until a match happens.
        """
        template = self.endpoints.get("basket", "/rest/basket/{id}")
        path = template.format(id=basket_id)
        return self.get(path, as_user=as_user)

    def get_user_exposure(self, as_user: str) -> requests.Response:
        """
        GET the endpoint under test for the Excessive Data Exposure finding.

        e.g. Hitting an endpoint deliberately to expose more user data than it should.
        """
        path = self.endpoints.get("user_exposure", "/rest/user/authentication-details")
        return self.get(path, as_user=as_user)

    def _require_user(self, role: str) -> dict[str, str]:
        """Fetch a role's credentials from config, and raise errors if it is missing"""
        user = self.test_users.get(role)
        if not user:
            raise ConfigError(
                f"No test user configured for role '{role}' in config file"
            )
        return user
