"""
GraphQL Information Disclosure tests (DVGA).

`IntrospectionExposureTest` and `FieldSuggestionInfoDisclosureTest` both
confirm ways an attacker can enumerate DVGA's schema without a legitimate
introspection query ever being intentionally exposed. They are distinct
findings: introspection exposure is a difficulty-mode toggle, while field
suggestions leak schema field names even when introspection is disabled,
because graphql-core computes them during query validation — a phase that
runs before any of DVGA's resolver-level middleware, including
`IntrospectionMiddleware`, ever executes.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import requests

from src.utils.dvga_client import DVGAClient
from src.utils.results_logger import RunLogger
from src.vulnerabilities.base import (
    AssertionRole,
    Severity,
    VulnerabilityResult,
    VulnerabilityTest,
)

logger = logging.getLogger(__name__)


def _parse_json(resp: requests.Response) -> Optional[dict[str, Any]]:
    try:
        return resp.json()
    except ValueError:
        return None


class IntrospectionExposureTest(VulnerabilityTest):
    """
    Confirms whether DVGA's `__schema` introspection field is reachable.

    `IntrospectionMiddleware` rejects any query resolving `__schema`, but
    only when the server is in hard difficulty mode — the check is skipped
    entirely under `helpers.is_level_easy()`. DVGA ships in easy mode by
    default on a fresh container, so introspection is exposed out of the
    box rather than needing to be turned on.
    """

    name = "introspection_exposure"
    owasp_category = "API8:2023 Security Misconfiguration"

    def __init__(self, architecture: str, target: str, client: DVGAClient) -> None:
        super().__init__(architecture, target)
        self.client = client

    def run(self) -> list[VulnerabilityResult]:
        cfg = self.client.scan_config.get("introspection_exposure", {})
        probe_query = cfg.get("probe_query", "{ __schema { queryType { name } } }")

        self.client.set_difficulty("hard")
        blocked_result = self._test_hard_mode_blocks_introspection(probe_query)

        self.client.set_difficulty("easy")
        exposed_result = self._test_easy_mode_allows_introspection(probe_query)

        return [blocked_result, exposed_result]

    def _test_hard_mode_blocks_introspection(
        self, probe_query: str
    ) -> VulnerabilityResult:
        """Baseline: hard mode's IntrospectionMiddleware must reject `__schema`."""
        resp = self.client.query(probe_query)
        data = _parse_json(resp) or {}
        errors = data.get("errors")

        blocked = bool(errors) and data.get("data") is None
        return self._result(
            passed=blocked,
            severity=Severity.LOW,
            evidence=(
                f"query {probe_query!r} (hard mode) -> HTTP {resp.status_code}, "
                f"errors={errors!r} "
                f"({'rejected, as expected' if blocked else 'unexpectedly executed — baseline unreliable'})."
            ),
            request_summary=f"POST /graphql query={probe_query!r} (hard mode)",
            response_summary=f"HTTP {resp.status_code}; blocked={blocked}",
            assertion_role=AssertionRole.CONTROL,
        )

    def _test_easy_mode_allows_introspection(
        self, probe_query: str
    ) -> VulnerabilityResult:
        """Bypass: DVGA's default (easy) mode leaves introspection reachable."""
        resp = self.client.query(probe_query)
        data = _parse_json(resp) or {}
        query_type = (data.get("data") or {}).get("__schema", {}).get("queryType")

        confirmed = (
            resp.status_code == 200 and not data.get("errors") and bool(query_type)
        )

        evidence = f"query {probe_query!r} (easy mode, the container's default) -> HTTP {resp.status_code}."
        if confirmed:
            evidence += (
                f" Returned {query_type!r} — introspection succeeds in the server's "
                "default difficulty mode, exposing the full schema (every query, "
                "mutation, and type) to an unauthenticated client with no prior "
                "reconnaissance needed."
            )

        return self._result(
            passed=not confirmed,
            severity=Severity.MEDIUM if confirmed else Severity.LOW,
            evidence=evidence,
            request_summary=f"POST /graphql query={probe_query!r} (easy mode)",
            response_summary=f"HTTP {resp.status_code}; queryType={query_type!r}",
        )


class FieldSuggestionInfoDisclosureTest(VulnerabilityTest):
    """
    Confirms whether a misspelled field name leaks real field names via
    graphql-core's built-in "Did you mean" suggestion error.

    This is tested with the server left in hard mode (introspection
    disabled) specifically to show the leak is independent of
    `IntrospectionExposureTest`: query validation — where suggestions are
    computed — runs before DVGA's field-resolution middleware, so
    disabling introspection does not prevent schema enumeration through
    this error-message oracle.
    """

    name = "field_suggestion_info_disclosure"
    owasp_category = "API8:2023 Security Misconfiguration"

    def __init__(self, architecture: str, target: str, client: DVGAClient) -> None:
        super().__init__(architecture, target)
        self.client = client

    def run(self) -> list[VulnerabilityResult]:
        cfg = self.client.scan_config.get("field_suggestion_disclosure", {})
        valid_query = cfg.get("valid_field_query", "{ systemDebug }")
        misspelled_query = cfg.get("misspelled_field_query", "{ systemHealtx }")
        expected_suggestion = cfg.get("expected_suggested_field", "systemHealth")

        self.client.set_difficulty("hard")

        return [
            self._test_valid_field_no_error(valid_query),
            self._test_misspelled_field_leaks_suggestion(
                misspelled_query, expected_suggestion
            ),
        ]

    def _test_valid_field_no_error(self, valid_query: str) -> VulnerabilityResult:
        """Baseline: a correctly spelled field must resolve without a validation error."""
        resp = self.client.query(valid_query)
        data = _parse_json(resp) or {}
        errors = data.get("errors")

        clean = resp.status_code == 200 and not errors
        return self._result(
            passed=clean,
            severity=Severity.LOW,
            evidence=(
                f"query {valid_query!r} (hard mode) -> HTTP {resp.status_code}, "
                f"errors={errors!r} "
                f"({'resolved cleanly, as expected' if clean else 'unexpected error — baseline unreliable'})."
            ),
            request_summary=f"POST /graphql query={valid_query!r} (hard mode)",
            response_summary=f"HTTP {resp.status_code}; errors={errors!r}",
            assertion_role=AssertionRole.CONTROL,
        )

    def _test_misspelled_field_leaks_suggestion(
        self, misspelled_query: str, expected_suggestion: str
    ) -> VulnerabilityResult:
        """Bypass: a misspelled field name's validation error names the real field."""
        resp = self.client.query(misspelled_query)
        data = _parse_json(resp) or {}
        errors = data.get("errors") or []
        message = errors[0].get("message", "") if errors else ""

        confirmed = "did you mean" in message.lower() and expected_suggestion in message

        evidence = f"query {misspelled_query!r} (hard mode) -> HTTP {resp.status_code}, message={message!r}."
        if confirmed:
            evidence += (
                f" Error message suggests real field {expected_suggestion!r} despite "
                "introspection being disabled in hard mode — graphql-core's "
                "field-suggestion behaviour runs during query validation, a phase that "
                "precedes DVGA's IntrospectionMiddleware entirely, so schema field "
                "names remain enumerable via deliberately misspelled queries even with "
                "introspection turned off."
            )

        return self._result(
            passed=not confirmed,
            severity=Severity.MEDIUM if confirmed else Severity.LOW,
            evidence=evidence,
            request_summary=f"POST /graphql query={misspelled_query!r} (hard mode)",
            response_summary=f"HTTP {resp.status_code}; message={message!r}",
        )


def _print_results(results: list[VulnerabilityResult]) -> None:
    for result in results:
        status = "PASS" if result.passed else f"FAIL ({result.severity.value.upper()})"
        print(f"[{status}] {result.test_name} - {result.owasp_category}")
        print(f"  Evidence:  {result.evidence}")
        print(f"  Request:   {result.request_summary}")
        print(f"  Response:  {result.response_summary}")
        print()


def _wait_for_dvga(
    client: DVGAClient, timeout: float = 30.0, interval: float = 2.0
) -> None:
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

    with RunLogger("graphql", "dvga", "config/dvga.yaml") as run:
        introspection_results = IntrospectionExposureTest(
            architecture="graphql", target="dvga", client=dvga_client
        ).run()
        run.log_results(introspection_results)
        field_suggestion_results = FieldSuggestionInfoDisclosureTest(
            architecture="graphql", target="dvga", client=dvga_client
        ).run()
        run.log_results(field_suggestion_results)
        dvga_client.set_difficulty("easy")

    _print_results(introspection_results)
    _print_results(field_suggestion_results)


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        choices=["dvga"],
        default="dvga",
        help=(
            "Which target's container must be up. DVGA is currently this "
            "framework's only GraphQL target — requires "
            "docker-compose.dvga.yml to be running."
        ),
    )
    args = parser.parse_args()

    if args.target == "dvga":
        _run_dvga()
