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
            raise RuntimeError(
                f"Login response for '{role}' did not contain a token: {data}"
            )

        self._tokens[role] = token
        logger.info("Login '%s': token stored", role)
        return token

    def me(self, token: str) -> requests.Response:
        """
        Call the `me` query with an arbitrary token — legitimate or forged.
        Forged one for testing JWT-forgery authorization-bypass.
        """
        query = self.operations["me"]
        return self.query(query, variables={"token": token})
    
    """
    paste:
    - A simple text-snippet ('paste') storage and retrieval feature.
    - Its filter parameter is used as the injection point for testing SQL injection.
    - Its value is concatenated into a raw SQL clause server-side without parameterisation.
    """

    def create_paste(
        self, title: str, content: str, public: bool = True, burn: bool = False
    ) -> requests.Response:
        """Create a paste via the `createPaste` mutation."""
        mutation = self.operations["create_paste"]
        return self.mutate(
            mutation,
            variables={
                "title": title,
                "content": content,
                "public": public,
                "burn": burn,
            },
        )

    def pastes(
        self,
        public: Optional[bool] = None,
        filter: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> requests.Response:
        """Call the `pastes` query with an arbitrary `filter` value — literal or a SQL injection payload."""
        query = self.operations["pastes"]
        return self.query(
            query, variables={"public": public, "filter": filter, "limit": limit}
        )

    def system_debug(self, arg: Optional[str] = None) -> requests.Response:
        """Call the `systemDebug` query with an arbitrary `arg` value — literal or an OS command injection payload."""
        query = self.operations["system_debug"]
        return self.query(query, variables={"arg": arg})

    def forge_token(self, identity: str) -> str:
        """
        Build a JWT carrying the given `identity` claim.
        """
        return jwt.encode(
            {"identity": identity},
            "unused-arbitrary-signing-key-not-a-real-secret",
            algorithm="HS256",
        )

    def set_difficulty(self, level: str) -> requests.Response:
        """
        Switch DVGA's runtime difficulty mode (easy/hard).
        Persisted server-side in DVGA's own database, not a per-request setting.
        """
        path = self.scan_config.get(
            "difficulty_endpoint", "/difficulty/{level}"
        ).format(level=level)
        return self.get(path)
    
    """
    GraphiQL is a built-in interactive web IDE that many GraphQL servers ship 
    with for development. It's a browser page where a developer can type queries, 
    see the schema, run them, and see results live. It is basically a debugging/testing 
    console sitting right on top of the API.

    Its a tool for developer only but not for public in production envionrment.
    If not properly configured or never disabled, attacker can do a recon to probe the API.
    """

    def graphiql_cookie(self) -> Optional[str]:
        """Get current value of the cookie."""
        cookie_name = self.scan_config.get("interface_protection", {}).get(
            "cookie_name", "env"
        )
        return self.session.cookies.get(cookie_name)

    def prime_graphiql_cookie(self) -> requests.Response:
        """Go to the root page in which DVGA sets its GraphiQL protection cookie."""
        return self.get("/")

    def set_graphiql_cookie(self, value: str) -> None:
        """Override (to attack) the GraphiQL protection cookie client-side."""
        cookie_name = self.scan_config.get("interface_protection", {}).get(
            "cookie_name", "env"
        )
        domain = urlparse(self.base_url).hostname
        for cookie in list(self.session.cookies):
            if cookie.name == cookie_name:
                self.session.cookies.clear(cookie.domain, cookie.path, cookie.name)
        self.session.cookies.set(cookie_name, value, domain=domain, path="/")

    def graphiql_query(self, query: str, **kwargs: Any) -> requests.Response:
        """Execute a GraphQL document through the `/graphiql` (after forging the cookie)."""
        path = self.scan_config.get("interface_protection", {}).get(
            "graphiql_path", "/graphiql"
        )
        return self.query(query, path=path, **kwargs)

    def _require_user(self, role: str) -> dict[str, str]:
        """Fetch a role's credentials from config, and raise errors if it is missing"""
        user = self.test_users.get(role)
        if not user:
            raise ConfigError(
                f"No test user configured for role '{role}' in config file"
            )
        return user
