"""
GraphQL Denial of Service tests (DVGA).

`DeepNestingDoSTest` and `BatchQueryDoSTest` are both resource-consumption
findings rather than clean pass/fail exploits — "vulnerable" is a matter of
degree (how deep, how large a batch) rather than a single boolean outcome.
Each test states this limitation directly in its evidence and stops short
of claiming a precise severity threshold DVGA itself does not define.
"""

from __future__ import annotations

import logging
import time
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


class DeepNestingDoSTest(VulnerabilityTest):
    """
    Confirms whether arbitrarily deep, cyclic queries are rejected.

    `DepthProtectionMiddleware` rejects a query once
    `parser.get_depth()` — a count of literal '{' tokens in the raw query
    text, not real AST depth — exceeds `config.MAX_DEPTH` (8), but only
    when the server is in hard difficulty mode. DVGA's schema exposes a
    cyclic relation (`PasteObject.owner` -> `OwnerObject.pastes` ->
    `PasteObject.owner` -> ...) with no depth limit of its own, so in the
    server's default easy mode a deeply nested query executes in full,
    with response size growing combinatorially at each additional level.
    """

    name = "deep_nesting_dos"
    owasp_category = "API4:2023 Unrestricted Resource Consumption"

    def __init__(self, architecture: str, target: str, client: DVGAClient) -> None:
        super().__init__(architecture, target)
        self.client = client

    def run(self) -> list[VulnerabilityResult]:
        cfg = self.client.scan_config.get("deep_nesting_dos", {})
        shallow_query = cfg.get(
            "shallow_query", "{ pastes(public: true) { owner { pastes { title } } } }"
        )
        deep_query = cfg.get(
            "deep_query",
            "{ pastes { owner { pastes { owner { pastes { owner { pastes { "
            "owner { pastes { title } } } } } } } } } }",
        )

        self.client.set_difficulty("hard")
        results = [
            self._test_hard_mode_allows_shallow_query(shallow_query),
            self._test_hard_mode_rejects_deep_query(deep_query),
        ]

        self.client.set_difficulty("easy")
        results.append(self._test_easy_mode_executes_deep_query(deep_query))
        return results

    def _test_hard_mode_allows_shallow_query(
        self, shallow_query: str
    ) -> VulnerabilityResult:
        """Baseline: hard mode must not reject a query under the depth threshold."""
        resp = self.client.query(shallow_query)
        data = _parse_json(resp) or {}
        errors = data.get("errors")

        allowed = resp.status_code == 200 and not errors
        return self._result(
            passed=allowed,
            severity=Severity.LOW,
            evidence=(
                f"query {shallow_query!r} (hard mode, under MAX_DEPTH) -> "
                f"HTTP {resp.status_code}, errors={errors!r} "
                f"({'allowed, as expected' if allowed else 'unexpectedly rejected — baseline unreliable'})."
            ),
            request_summary=f"POST /graphql query={shallow_query!r} (hard mode)",
            response_summary=f"HTTP {resp.status_code}",
            assertion_role=AssertionRole.CONTROL,
        )

    def _test_hard_mode_rejects_deep_query(
        self, deep_query: str
    ) -> VulnerabilityResult:
        """Baseline: hard mode's DepthProtectionMiddleware must reject a query over the depth threshold."""
        resp = self.client.query(deep_query)
        data = _parse_json(resp) or {}
        errors = data.get("errors") or []
        message = errors[0].get("message", "") if errors else ""

        rejected = "depth" in message.lower()
        return self._result(
            passed=rejected,
            severity=Severity.LOW,
            evidence=(
                f"query (depth-exceeding, cyclic owner/pastes chain) (hard mode) -> "
                f"HTTP {resp.status_code}, message={message!r} "
                f"({'rejected, as expected' if rejected else 'unexpectedly executed — baseline unreliable'})."
            ),
            request_summary="POST /graphql query=<deep_query> (hard mode)",
            response_summary=f"HTTP {resp.status_code}; message={message!r}",
            assertion_role=AssertionRole.CONTROL,
        )

    def _test_easy_mode_executes_deep_query(
        self, deep_query: str
    ) -> VulnerabilityResult:
        """Bypass: DVGA's default (easy) mode has no depth limit at all.

        Response size grows combinatorially with each additional
        owner/pastes level, since every level expands a list rather than a
        single record — so this request can legitimately exceed the
        client's own configured timeout as more paste data accumulates in
        the container across runs. A timeout is treated as confirming the
        finding rather than as a transport failure: it demonstrates
        resource exhaustion more directly than a slow-but-completed
        response would.
        """
        start = time.monotonic()
        try:
            resp = self.client.query(deep_query)
        except requests.exceptions.RequestException as exc:
            elapsed = time.monotonic() - start
            evidence = (
                f"query (same depth-exceeding, cyclic owner/pastes chain) "
                f"(easy mode, the container's default) -> did not complete within "
                f"{elapsed:.3f}s ({exc.__class__.__name__}). No depth limit is in "
                "effect in easy mode, and response size grows combinatorially with "
                "each additional owner/pastes level, so the request exhausted the "
                "client's own timeout rather than returning an error — stronger "
                "evidence of unrestricted resource consumption than a "
                "slow-but-completed response would be."
            )
            return self._result(
                passed=False,
                severity=Severity.HIGH,
                evidence=evidence,
                request_summary="POST /graphql query=<deep_query> (easy mode)",
                response_summary=f"no response; timed out after {elapsed:.3f}s",
            )

        elapsed = time.monotonic() - start
        data = _parse_json(resp) or {}

        confirmed = resp.status_code == 200 and not data.get("errors")

        evidence = (
            f"query (same depth-exceeding, cyclic owner/pastes chain) "
            f"(easy mode, the container's default) -> HTTP {resp.status_code} "
            f"in {elapsed:.3f}s."
        )
        if confirmed:
            evidence += (
                " Executed in full with no depth limit in effect — response size grows "
                "combinatorially with each additional owner/pastes level rather than "
                "linearly, since each level expands a list. Whether a given depth "
                "constitutes a practical DoS is a matter of degree DVGA does not itself "
                "define a threshold for; this result establishes that no ceiling exists "
                "at all in the server's default mode, rather than asserting a specific "
                "resource-exhaustion outcome."
            )

        return self._result(
            passed=not confirmed,
            severity=Severity.MEDIUM if confirmed else Severity.LOW,
            evidence=evidence,
            request_summary="POST /graphql query=<deep_query> (easy mode)",
            response_summary=f"HTTP {resp.status_code}; elapsed={elapsed:.3f}s",
        )


class BatchQueryDoSTest(VulnerabilityTest):
    """
    Confirms whether an oversized batched request is accepted unchecked.

    The `/graphql` view is registered with `batch=True`
    (flask-graphql/graphql-server), accepting a JSON array of query
    objects in a single HTTP request. No code path enforces a maximum
    array length, and — unlike introspection or depth protection — this is
    not gated by difficulty mode either: `CostProtectionMiddleware` and
    `DepthProtectionMiddleware` evaluate each array element independently
    and never sum across the whole batch, so a single request can still
    multiply server-side work by an arbitrary factor regardless of mode.
    """

    name = "batch_query_dos"
    owasp_category = "API4:2023 Unrestricted Resource Consumption"

    def __init__(self, architecture: str, target: str, client: DVGAClient) -> None:
        super().__init__(architecture, target)
        self.client = client

    def run(self) -> list[VulnerabilityResult]:
        cfg = self.client.scan_config.get("batch_query_dos", {})
        probe_query = cfg.get("probe_query", "{ systemHealth }")
        control_size = cfg.get("control_batch_size", 2)
        oversized_size = cfg.get("oversized_batch_size", 30)

        return [
            self._test_control_small_batch_succeeds(probe_query, control_size),
            self._test_oversized_batch_accepted_unchecked(probe_query, oversized_size),
        ]

    def _test_control_small_batch_succeeds(
        self, probe_query: str, control_size: int
    ) -> VulnerabilityResult:
        """Baseline: a small, legitimate-sized batch must succeed."""
        resp = self.client.execute_batch([probe_query] * control_size)
        data: Any = _parse_json(resp) or []

        succeeded = (
            resp.status_code == 200
            and isinstance(data, list)
            and len(data) == control_size
        )
        return self._result(
            passed=succeeded,
            severity=Severity.LOW,
            evidence=(
                f"Batch of {control_size} x {probe_query!r} -> HTTP {resp.status_code}, "
                f"{len(data) if isinstance(data, list) else 'non-list'} response(s) "
                f"({'succeeded, as expected' if succeeded else 'unexpected failure — baseline unreliable'})."
            ),
            request_summary=f"POST /graphql batch(n={control_size}) query={probe_query!r}",
            response_summary=f"HTTP {resp.status_code}",
            assertion_role=AssertionRole.CONTROL,
        )

    def _test_oversized_batch_accepted_unchecked(
        self, probe_query: str, oversized_size: int
    ) -> VulnerabilityResult:
        """Bypass: an oversized batch is executed in full with no rejection or throttling."""
        single_start = time.monotonic()
        single_resp = self.client.query(probe_query)
        single_elapsed = time.monotonic() - single_start

        batch_start = time.monotonic()
        batch_resp = self.client.execute_batch([probe_query] * oversized_size)
        batch_elapsed = time.monotonic() - batch_start

        data: Any = _parse_json(batch_resp) or []
        accepted_in_full = (
            batch_resp.status_code == 200
            and isinstance(data, list)
            and len(data) == oversized_size
            and single_resp.status_code == 200
        )

        evidence = (
            f"Single {probe_query!r} -> HTTP {single_resp.status_code} in "
            f"{single_elapsed:.3f}s. Batch of {oversized_size} x {probe_query!r} in one "
            f"request -> HTTP {batch_resp.status_code} in {batch_elapsed:.3f}s, "
            f"{len(data) if isinstance(data, list) else 'non-list'} response(s)."
        )
        if accepted_in_full:
            evidence += (
                " Every element of the oversized batch executed and returned a result "
                "— no batch-size limit rejected or truncated the request. Total batch "
                "latency scaling with batch size (rather than being flat, as a "
                "size-capped or rate-limited endpoint would show) is offered as "
                "corroborating context, not the pass/fail signal itself: like "
                "DeepNestingDoSTest, the practical severity of a given batch size is a "
                "matter of degree this test does not attempt to quantify precisely — "
                "the finding is that no ceiling exists at all, in either difficulty mode."
            )

        return self._result(
            passed=not accepted_in_full,
            severity=Severity.MEDIUM if accepted_in_full else Severity.LOW,
            evidence=evidence,
            request_summary=f"POST /graphql batch(n={oversized_size}) query={probe_query!r}",
            response_summary=(
                f"HTTP {batch_resp.status_code}; elapsed={batch_elapsed:.3f}s "
                f"(single={single_elapsed:.3f}s)"
            ),
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
    dvga_client.set_difficulty("easy")

    with RunLogger("graphql", "dvga", "config/dvga.yaml") as run:
        deep_nesting_results = DeepNestingDoSTest(
            architecture="graphql", target="dvga", client=dvga_client
        ).run()
        run.log_results(deep_nesting_results)
        batch_query_results = BatchQueryDoSTest(
            architecture="graphql", target="dvga", client=dvga_client
        ).run()
        run.log_results(batch_query_results)
        dvga_client.set_difficulty("easy")

    _print_results(deep_nesting_results)
    _print_results(batch_query_results)


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
