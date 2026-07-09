"""
Generic REST API client base for interacting with vulnerable test targets.
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


class RESTAPIClient:
    """
    Usage:
    client = SomeTargetClient.from_config("config/some_target.yaml")
    resp = client.get("/some/path", as_user="attacker")
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
    def from_config(cls, config_path: str | Path) -> "RESTAPIClient":
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
