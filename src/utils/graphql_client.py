"""
Generic GraphQL API client base (a wrapper) for interacting with vulnerable test targets.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

import requests
import yaml

logger = logging.getLogger(__name__)


class ConfigError(Exception):
    """Raised when the target (YAML) config file is missing or malformed."""


class GraphQLAPIClient:
    """
    Usage:
    client = SomeTargetClient.from_config("config/some_target.yaml")
    resp = client.query("{ someField }", as_user="attacker")
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        target = config.get("target", {})
        self.base_url: str = target["base_url"].rstrip("/")
        self.endpoint_path: str = target.get("endpoint_path", "/graphql")
        self.timeout: int = target.get("timeout_seconds", 10)

        auth_cfg = config.get("auth", {})
        self.token_header: str = auth_cfg.get("token_header", "Authorization")
        self.token_prefix: str = auth_cfg.get("token_prefix", "Bearer")

        self.test_users: dict[str, dict[str, str]] = config.get("test_users", {})

        # role name -> token string, populated by a target-specific login()
        self._tokens: dict[str, str] = {}

        # Public: case-specific tests that need HTTP behavior outside the
        # query/mutation transport (cookies, non-GraphQL routes) work
        # directly against this session rather than opening a second one.
        self.session = requests.Session()

    @classmethod
    def from_config(cls, config_path: str | Path) -> "GraphQLAPIClient":
        """
        Build a client (object) from a target's YAML config file.
        The object includes base_url, timeout, endpoint_path, endpoint_url, 
        test_users, _tokens, session, etc.
        """
        path = Path(config_path)
        if not path.exists():
            raise ConfigError(f"Config file not found: {path}")
        with path.open("r") as f:
            data = yaml.safe_load(f)
        if not data or "target" not in data:
            raise ConfigError(f"Config file missing required 'target' section: {path}")
        return cls(data)

    @property
    def endpoint_url(self) -> str:
        """For only one endpoint (same URL)"""
        return f"{self.base_url}{self.endpoint_path}"

    def _url(self, path: str) -> str:
        """For non-GraphQL route (get() method only) e.g. /graphiql"""
        return f"{self.base_url}{path}"

    def _headers_for(self, as_user: Optional[str]) -> dict[str, str]:
        """
        Build the auth header (Authorization: Bearer <token>).
        Only work with token created from login.
        """
        headers = {}
        if as_user:
            token = self._tokens.get(as_user)
            if not token:
                raise RuntimeError(
                    f"No token stored for user role '{as_user}'. Call login() first."
                )
            headers[self.token_header] = f"{self.token_prefix} {token}"
        return headers

    def execute(
        self,
        query: str,
        variables: Optional[dict[str, Any]] = None,
        operation_name: Optional[str] = None,
        as_user: Optional[str] = None,
        path: Optional[str] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """
        Build a GraphQL request body and POST it.
        """
        body: dict[str, Any] = {"query": query}
        if variables is not None:
            body["variables"] = variables
        if operation_name is not None:
            body["operationName"] = operation_name

        url = f"{self.base_url}{path}" if path is not None else self.endpoint_url
        return self.session.post(
            url,
            json=body,
            headers=self._headers_for(as_user),
            timeout=self.timeout,
            **kwargs,
        )

    def query(self, query: str, **kwargs: Any) -> requests.Response:
        return self.execute(query, **kwargs)

    def mutate(self, mutation: str, **kwargs: Any) -> requests.Response:
        return self.execute(mutation, **kwargs)

    def execute_batch(
        self,
        queries: list[str],
        as_user: Optional[str] = None,
        path: Optional[str] = None,
    ) -> requests.Response:
        """
        Send multiple query/mutation documents as a 
        single batched HTTP request (a JSON array body). 
        Targets are expected to either enforce a batch
        size limit or execute the whole array unconditionally.
        """
        body = [{"query": q} for q in queries]
        url = f"{self.base_url}{path}" if path is not None else self.endpoint_url
        return self.session.post(
            url,
            json=body,
            headers=self._headers_for(as_user),
            timeout=self.timeout,
        )

    def get(
        self, path: str, as_user: Optional[str] = None, **kwargs: Any
    ) -> requests.Response:
        """Raw GET against the target's base_url."""
        return self.session.get(
            self._url(path),
            headers=self._headers_for(as_user),
            timeout=self.timeout,
            **kwargs,
        )
