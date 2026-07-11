"""
crAPI-specific REST API client.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import requests

from src.utils.api_client import ConfigError, RESTAPIClient

logger = logging.getLogger(__name__)


class CrAPIClient(RESTAPIClient):
    """RESTAPIClient subclass for crAPI's auth flow and coupon endpoints."""

    @property
    def scan_config(self) -> dict[str, Any]:
        return self._config.get("scan", {})

    def signup(self, role: str) -> requests.Response:
        """
        Register a test user identified by role
        """
        user = self._require_user(role)
        path = self.endpoints.get("signup", "/identity/api/auth/signup")
        payload = {
            "name": user["name"],
            "email": user["email"],
            "password": user["password"],
            "number": user["number"],
        }
        resp = self.session.post(self._url(path), json=payload, timeout=self.timeout)
        logger.info("Signup '%s': %s -> %s", role, path, resp.status_code)
        return resp

    def login(self, role: str) -> str:
        """
        Log in a test user and store their token for later requests.
        """
        user = self._require_user(role)
        path = self.endpoints.get("login", "/identity/api/auth/login")
        payload = {"email": user["email"], "password": user["password"]}
        resp = self.session.post(self._url(path), json=payload, timeout=self.timeout)
        resp.raise_for_status()

        data = resp.json()
        token = data.get("token")
        if not token:
            raise RuntimeError(
                f"Login response for '{role}' did not contain a token: {data}"
            )

        self._tokens[role] = token
        logger.info("Login '%s': token stored", role)
        return token

    def validate_coupon(
        self, body: dict[str, Any], as_user: Optional[str]
    ) -> requests.Response:
        """
        POST to the NoSQL-injectable validate-coupon endpoint.
        """
        path = self.endpoints.get(
            "validate_coupon", "/community/api/v2/coupon/validate-coupon"
        )
        resp = self.session.post(
            self._url(path),
            json=body,
            headers=self._headers_for(as_user),
            timeout=self.timeout,
        )
        return resp

    def apply_coupon(
        self, coupon_code: str, amount: int, as_user: Optional[str]
    ) -> requests.Response:
        """P
        OST to the SQL-injectable apply_coupon endpoint.
        """
        path = self.endpoints.get("apply_coupon", "/workshop/api/shop/apply_coupon")
        resp = self.session.post(
            self._url(path),
            json={"coupon_code": coupon_code, "amount": amount},
            headers=self._headers_for(as_user),
            timeout=self.timeout,
        )
        return resp

    def _require_user(self, role: str) -> dict[str, str]:
        user = self.test_users.get(role)
        if not user:
            raise ConfigError(
                f"No test user configured for role '{role}' in config file"
            )
        return user
