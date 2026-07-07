"""
crAPI-specific REST API client.

Extends RESTAPIClient with crAPI's exact auth flow and endpoint shapes:
signup/login payloads of {name, email, password, number} (email-based login,
not username like VAmPI's), the `token` field name in login responses, and
the coupon validate/apply endpoints used by the NoSQL/SQL injection tests.

crAPI has no single reseed endpoint (see CLAUDE.md, State Management Per
Target) — the coupons collection is seeded once by crapi-community on first
boot and persists in the mongodb-data volume across runs, and there is no
equivalent of VAmPI's /createdb. Tests that need a guaranteed applied_coupon
row (see SQLiApplyCouponTest) create it themselves via apply_coupon() rather
than relying on leftover state from a previous run.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import requests

from src.utils.api_client import ConfigError, RESTAPIClient

logger = logging.getLogger(__name__)


class CrAPIClient(RESTAPIClient):
    """RESTAPIClient subclass wired to crAPI's auth flow and coupon endpoints."""

    @property
    def scan_config(self) -> dict[str, Any]:
        """The config file's `scan:` section — see VAmPIClient.scan_config
        for why vulnerability modules read scan scope through here rather
        than the client's private config dict."""
        return self._config.get("scan", {})

    def signup(self, role: str) -> requests.Response:
        """Register a test user identified by role (e.g. 'attacker', 'victim').

        crAPI's SignUpForm requires all four fields (name, email, password,
        number) — confirmed against services/identity/src/main/java/com/crapi
        /model/SignUpForm.java (@NotBlank on all of them) and empirically
        against the live container.
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
        """Log in a test user and store their token for later requests.

        Unlike VAmPI's `auth_token` field, crAPI's login response uses
        `token` (confirmed empirically: {"token": ..., "type": "Bearer", ...}).
        """
        user = self._require_user(role)
        path = self.endpoints.get("login", "/identity/api/auth/login")
        payload = {"email": user["email"], "password": user["password"]}
        resp = self.session.post(self._url(path), json=payload, timeout=self.timeout)
        resp.raise_for_status()

        data = resp.json()
        token = data.get("token")
        if not token:
            raise RuntimeError(f"Login response for '{role}' did not contain a token: {data}")

        self._tokens[role] = token
        logger.info("Login '%s': token stored", role)
        return token

    def validate_coupon(
        self, body: dict[str, Any], as_user: Optional[str]
    ) -> requests.Response:
        """POST to the NoSQL-injectable validate-coupon endpoint.

        `body` is passed through as the raw JSON payload — the vulnerability
        under test is that crapi-community unmarshals this body directly
        into a MongoDB filter document (bson.M) with no shape validation,
        so callers may pass either a plain string coupon_code or a Mongo
        operator object (e.g. {"coupon_code": {"$ne": 1}}).
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
        """POST to the SQL-injectable apply_coupon endpoint.

        `coupon_code` is passed through raw — the vulnerability under test
        is that crapi-workshop string-concatenates it directly into a raw
        SQL query with no parameterisation, before any check that the
        coupon exists.
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
            raise ConfigError(f"No test user configured for role '{role}' in config file")
        return user
