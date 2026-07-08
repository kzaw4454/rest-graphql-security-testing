"""
OWASP Juice Shop-specific REST API client.

Extends RESTAPIClient with Juice Shop's exact auth flow and endpoint shapes:
register/login payloads of {email, password[, passwordRepeat]}, the
`authentication.token` field name in login responses, and a basket ID
(`authentication.bid`) that arrives for free at login — unlike VAmPI/crAPI,
no separate discovery call is needed to learn a user's own object ID.

Juice Shop has no reseed endpoint reachable mid-session (see
docker/docker-compose.juiceshop.yml's header comment: it only resets by
restarting the container) and confirmed empirically that a duplicate email
on `register()` 400s ("email must be unique"). This mirrors crAPI's
state-management problem (see CLAUDE.md, State Management Per Target, and
src/vulnerabilities/injection.py's `_fresh_synthetic_login`) more than
VAmPI's /createdb pattern — callers must generate a fresh randomized
identity per run rather than reusing config's static test_users entries as
literals.
"""

from __future__ import annotations

import logging
from typing import Any

import requests

from src.utils.api_client import ConfigError, RESTAPIClient

logger = logging.getLogger(__name__)


class JuiceShopClient(RESTAPIClient):
    """RESTAPIClient subclass wired to Juice Shop's auth flow and basket IDs."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        # role -> basket id, populated by login(). Juice Shop returns this
        # directly in the login response (see login()'s docstring), so no
        # separate per-role discovery call is needed the way VAmPI's BOLA
        # test needs a setup POST to create a book first.
        self._basket_ids: dict[str, int] = {}

    @property
    def scan_config(self) -> dict[str, Any]:
        """The config file's `scan:` section — see VAmPIClient.scan_config
        for why vulnerability modules read scan scope through here rather
        than the client's private config dict."""
        return self._config.get("scan", {})

    def register(self, role: str) -> requests.Response:
        """Register a test user identified by role (e.g. 'attacker', 'victim').

        Confirmed empirically against a live bkimminich/juice-shop:latest
        container: `POST /api/Users/` with just {email, password,
        passwordRepeat} returns HTTP 201 — no security-question field is
        required at the API level, despite the registration UI form
        presenting one. A duplicate email 400s ("email must be unique"),
        confirming the no-reseed state-management concern in this module's
        docstring is real and not merely theoretical.
        """
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
        """Log in a test user, storing their token and basket id.

        Confirmed empirically: the response is shaped exactly as
        `{"authentication": {"token": ..., "bid": <int>, "umail": ...}}` —
        the basket id is available for free here, unlike VAmPI's BOLA test
        which must create a book as a separate setup step.
        """
        user = self._require_user(role)
        path = self.endpoints.get("login", "/rest/user/login")
        payload = {"email": user["email"], "password": user["password"]}
        resp = self.session.post(self._url(path), json=payload, timeout=self.timeout)
        resp.raise_for_status()

        data = resp.json()
        auth = data.get("authentication", {})
        token = auth.get("token")
        if not token:
            raise RuntimeError(f"Login response for '{role}' did not contain a token: {data}")

        self._tokens[role] = token
        bid = auth.get("bid")
        if bid is not None:
            self._basket_ids[role] = bid
        logger.info("Login '%s': token stored, bid=%s", role, bid)
        return token

    def basket_id_for(self, role: str) -> int:
        """The basket id captured from `role`'s login response.

        Raises if login() hasn't been called yet for this role — mirrors
        `_headers_for`'s "call login() first" contract in the base client.
        """
        bid = self._basket_ids.get(role)
        if bid is None:
            raise RuntimeError(
                f"No basket id stored for user role '{role}'. Call login() first."
            )
        return bid

    def get_basket(self, basket_id: int, as_user: str | None) -> requests.Response:
        """GET a basket by raw id — the object under test for the BOLA finding."""
        template = self.endpoints.get("basket", "/rest/basket/{id}")
        path = template.format(id=basket_id)
        return self.get(path, as_user=as_user)

    def get_user_exposure(self, as_user: str) -> requests.Response:
        """GET the endpoint under test for the Excessive Data Exposure finding."""
        path = self.endpoints.get("user_exposure", "/rest/user/authentication-details")
        return self.get(path, as_user=as_user)

    def _require_user(self, role: str) -> dict[str, str]:
        user = self.test_users.get(role)
        if not user:
            raise ConfigError(f"No test user configured for role '{role}' in config file")
        return user
