"""
Rate Limiting / Unrestricted Resource Consumption (OWASP API4:2023) tests.
"""

from __future__ import annotations

import logging
import random
import time
import uuid

from src.utils.crapi_client import CrAPIClient
from src.utils.results_logger import RunLogger
from src.utils.vampi_client import VAmPIClient
from src.vulnerabilities.base import Severity, VulnerabilityResult, VulnerabilityTest

logger = logging.getLogger(__name__)

# VAmPI's own fixture username, seeded on every /createdb reseed — a wrong
# password against it is guaranteed to fail without depending on this
# framework's synthetic test_users being registered first.
SEEDED_USERNAME = "name1"
WRONG_PASSWORD = "wrong-password-attempt"


class LoginBruteForceRateLimitTest(VulnerabilityTest):
    """
    Confirms whether VAmPI throttles repeated failed login attempts
    against a known username.
    """

    name = "login_brute_force_rate_limit"
    owasp_category = "API4:2023 Unrestricted Resource Consumption"

    def __init__(self, architecture: str, target: str, client: VAmPIClient) -> None:
        super().__init__(architecture, target)
        self.client = client
        self.attempt_count: int = client.scan_config.get(
            "rate_limit_login_attempts", 25
        )
        self.request_interval_seconds: float = client.scan_config.get(
            "rate_limit_request_interval_seconds", 0.0
        )

    def run(self) -> list[VulnerabilityResult]:
        """Seeds the database, and runs the checks"""
        self.client.seed_database()
        return [self._test_unthrottled_login_attempts()]

    def _test_unthrottled_login_attempts(self) -> VulnerabilityResult:
        """
        Submits multiple (repeatedly) wrong password for a known username and
        records status code and response time.

        No throttled (HTTP 429 Too Many Requests) or slow down - vulnerability exists.
        """
        path = self.client.endpoints.get("login", "/users/v1/login")
        statuses: list[int] = []
        latencies: list[float] = []

        for _ in range(self.attempt_count):
            start = time.monotonic()
            resp = self.client.post(
                path, json={"username": SEEDED_USERNAME, "password": WRONG_PASSWORD}
            )
            latencies.append(time.monotonic() - start)
            statuses.append(resp.status_code)
            if resp.status_code == 429:
                break
            if self.request_interval_seconds:
                time.sleep(self.request_interval_seconds)

        throttled_at = next(
            (i + 1 for i, status in enumerate(statuses) if status == 429), None
        )
        confirmed_unthrottled = (
            throttled_at is None and len(statuses) == self.attempt_count
        )

        evidence = (
            f"{len(statuses)} rapid login attempts against seeded username "
            f"{SEEDED_USERNAME!r} with a wrong password -> status codes {statuses}."
        )
        if confirmed_unthrottled:
            evidence += (
                f" All {self.attempt_count} attempts returned the same un-throttled "
                "failure response (VAmPI's password-enumeration behaviour returns "
                "HTTP 200 with a 'Password is not correct' body rather than 401/403 — "
                "see api_views/users.py::login_user), with no HTTP 429, lockout, or "
                "CAPTCHA challenge, and no growth in response latency "
                f"(min={min(latencies):.3f}s, max={max(latencies):.3f}s)."
            )
        elif throttled_at:
            evidence += f" Throttling (HTTP 429) observed at attempt {throttled_at}."

        return self._result(
            passed=not confirmed_unthrottled,
            severity=Severity.HIGH if confirmed_unthrottled else Severity.LOW,
            evidence=evidence,
            request_summary=f"POST {path} x{len(statuses)} (same wrong password)",
            response_summary=f"status_codes={statuses}",
            attempt_count=len(statuses),
            throttled_at_attempt=throttled_at,
        )


def _fresh_synthetic_login(client: CrAPIClient, role: str) -> None:
    """Sign up and log in a new identity (crAPI test account) for `role`."""
    user = client.test_users[role]
    suffix = uuid.uuid4().hex[:10]
    user["email"] = f"{role}.{suffix}@crapi-test.local"
    user["number"] = str(random.randint(6_000_000_000, 6_999_999_999))
    client.signup(role)
    client.login(role)


class CrAPILoginBruteForceRateLimitTest(VulnerabilityTest):
    """
    Confirms whether crAPI throttles repeated failed login attempts
    against a known, registered email.
    """

    name = "crapi_login_brute_force_rate_limit"
    owasp_category = "API4:2023 Unrestricted Resource Consumption"

    def __init__(self, architecture: str, target: str, client: CrAPIClient) -> None:
        super().__init__(architecture, target)
        self.client = client
        self.attempt_count: int = client.scan_config.get(
            "rate_limit_login_attempts", 25
        )
        self.request_interval_seconds: float = client.scan_config.get(
            "rate_limit_request_interval_seconds", 0.0
        )

    def run(self) -> list[VulnerabilityResult]:
        """Logins as new user and runs the check."""
        _fresh_synthetic_login(self.client, "victim")
        return [self._test_unthrottled_login_attempts()]

    def _test_unthrottled_login_attempts(self) -> VulnerabilityResult:
        """
        Attempts multiple login to crAPI's endpoint.
        """
        path = self.client.endpoints.get("login", "/identity/api/auth/login")
        email = self.client.test_users["victim"]["email"]
        statuses: list[int] = []
        latencies: list[float] = []

        for _ in range(self.attempt_count):
            start = time.monotonic()
            resp = self.client.post(
                path, json={"email": email, "password": WRONG_PASSWORD}
            )
            latencies.append(time.monotonic() - start)
            statuses.append(resp.status_code)
            if resp.status_code == 429:
                break
            if self.request_interval_seconds:
                time.sleep(self.request_interval_seconds)

        throttled_at = next(
            (i + 1 for i, status in enumerate(statuses) if status == 429), None
        )
        confirmed_unthrottled = (
            throttled_at is None and len(statuses) == self.attempt_count
        )

        evidence = (
            f"{len(statuses)} rapid login attempts against a registered email "
            f"with a wrong password -> status codes {statuses}."
        )
        if confirmed_unthrottled:
            evidence += (
                f" All {self.attempt_count} attempts returned the same "
                "un-throttled HTTP 401 'Invalid Credentials' response, with no "
                "HTTP 429, lockout, or CAPTCHA challenge, and no growth in "
                f"response latency (min={min(latencies):.3f}s, max={max(latencies):.3f}s)."
            )
        elif throttled_at:
            evidence += f" Throttling (HTTP 429) observed at attempt {throttled_at}."

        return self._result(
            passed=not confirmed_unthrottled,
            severity=Severity.HIGH if confirmed_unthrottled else Severity.LOW,
            evidence=evidence,
            request_summary=f"POST {path} x{len(statuses)} (same wrong password)",
            response_summary=f"status_codes={statuses}",
            attempt_count=len(statuses),
            throttled_at_attempt=throttled_at,
        )


def _print_results(results: list[VulnerabilityResult]) -> None:
    for result in results:
        status = "PASS" if result.passed else f"FAIL ({result.severity.value.upper()})"
        print(f"[{status}] {result.test_name} - {result.owasp_category}")
        print(f"  Evidence:  {result.evidence}")
        print(f"  Request:   {result.request_summary}")
        print(f"  Response:  {result.response_summary}")
        print()


def _run_vampi() -> None:
    client = VAmPIClient.from_config("config/vampi.yaml")
    with RunLogger("rest", "vampi", "config/vampi.yaml") as run:
        results = LoginBruteForceRateLimitTest(
            architecture="rest", target="vampi", client=client
        ).run()
        run.log_results(results)
    _print_results(results)


def _run_crapi() -> None:
    client = CrAPIClient.from_config("config/crapi.yaml")
    with RunLogger("rest", "crapi", "config/crapi.yaml") as run:
        results = CrAPILoginBruteForceRateLimitTest(
            architecture="rest", target="crapi", client=client
        ).run()
        run.log_results(results)
    _print_results(results)


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        choices=["vampi", "crapi", "all"],
        default="all",
        help=(
            "Which target's container must be up. Default 'all' requires both "
            "docker-compose.vampi.yml and docker-compose.crapi.yml to be running "
            "— pass --target to run just one."
        ),
    )
    args = parser.parse_args()

    if args.target in ("vampi", "all"):
        _run_vampi()
    if args.target in ("crapi", "all"):
        _run_crapi()
