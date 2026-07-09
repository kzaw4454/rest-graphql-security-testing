from __future__ import annotations

import logging
from typing import Any, Optional
from urllib.parse import urlparse

import jwt
import requests

from src.utils.graphql_client import ConfigError, GraphQLAPIClient

logger = logging.getLogger(__name__)


class DVGAClient(GraphQLAPIClient):
    """GraphQLAPIClient for DVGA's auth flow, difficulty mode, and JWT handling."""

    @property
    def scan_config(self) -> dict[str, Any]:
        return self._config.get("scan", {})

    @property
    def operations(self) -> dict[str, str]:
        return self._config.get("operations", {})

    def login(self, role: str) -> str:
        """
        Authenticate via DVGA's `login` mutation and store the access
        token under `role`. DVGA has no register/signup mutation — the
        account must already exist in its seeded database.
        """
        user = self._require_user(role)
        mutation = self.operations["login"]
        resp = self.mutate(
            mutation,
            variables={"username": user["username"], "password": user["password"]},
        )
        resp.raise_for_status()

        data = resp.json()
        errors = data.get("errors")
        if errors:
            raise RuntimeError(f"Login failed for '{role}': {errors}")

        token = data.get("data", {}).get("login", {}).get("accessToken")
        if not token:
            raise RuntimeError(f"Login response for '{role}' did not contain a token: {data}")

        self._tokens[role] = token
        logger.info("Login '%s': token stored", role)
        return token

    def me(self, token: str) -> requests.Response:
        """Call the `me` query with an arbitrary token — legitimate or forged."""
        query = self.operations["me"]
        return self.query(query, variables={"token": token})

    def forge_token(self, identity: str) -> str:
        """
        Build a JWT carrying the given `identity` claim.
        """
        return jwt.encode(
            {"identity": identity}, "unused-arbitrary-signing-key-not-a-real-secret", algorithm="HS256"
        )

    def set_difficulty(self, level: str) -> requests.Response:
        """
        Switch DVGA's runtime difficulty mode (easy/hard). 
        Persisted server-side in DVGA's own database, not a per-request setting.
        """
        path = self.scan_config.get("difficulty_endpoint", "/difficulty/{level}").format(
            level=level
        )
        return self.get(path)

    def graphiql_cookie(self) -> Optional[str]:
        """Current value of the cookie gating the GraphiQL IDE route."""
        cookie_name = self.scan_config.get("interface_protection", {}).get(
            "cookie_name", "env"
        )
        return self.session.cookies.get(cookie_name)

    def prime_graphiql_cookie(self) -> requests.Response:
        """GET the root page so DVGA sets its GraphiQL protection cookie."""
        return self.get("/")

    def set_graphiql_cookie(self, value: str) -> None:
        """
        Override the GraphiQL protection cookie client-side.
        """
        cookie_name = self.scan_config.get("interface_protection", {}).get(
            "cookie_name", "env"
        )
        domain = urlparse(self.base_url).hostname
        for cookie in list(self.session.cookies):
            if cookie.name == cookie_name:
                self.session.cookies.clear(cookie.domain, cookie.path, cookie.name)
        self.session.cookies.set(cookie_name, value, domain=domain, path="/")

    def graphiql_query(self, query: str, **kwargs: Any) -> requests.Response:
        """
        Execute a GraphQL document through the `/graphiql`.
        """
        path = self.scan_config.get("interface_protection", {}).get(
            "graphiql_path", "/graphiql"
        )
        return self.query(query, path=path, **kwargs)

    def _require_user(self, role: str) -> dict[str, str]:
        user = self.test_users.get(role)
        if not user:
            raise ConfigError(f"No test user configured for role '{role}' in config file")
        return user
