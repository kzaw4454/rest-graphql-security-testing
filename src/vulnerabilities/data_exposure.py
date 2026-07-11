"""
Excessive Data Exposure (OWASP API3:2023) test against Juice Shop.
"""

from __future__ import annotations

import logging
import uuid

from src.utils.juiceshop_client import JuiceShopClient
from src.utils.results_logger import RunLogger
from src.vulnerabilities.base import Severity, VulnerabilityResult, VulnerabilityTest

logger = logging.getLogger(__name__)


class ExcessiveUserDataExposureTest(VulnerabilityTest):
    """
    Confirms whether Juice Shop's authentication-details endpoint leaks
    other users' data to an ordinary, non-admin authenticated user.
    """

    name = "excessive_user_data_exposure"
    owasp_category = "API3:2023 Excessive Data Exposure"

    def __init__(self, architecture: str, target: str, client: JuiceShopClient) -> None:
        super().__init__(architecture, target)
        self.client = client
        self.email_field: str = client.scan_config.get("exposure_email_field", "email")
        self.password_field: str = client.scan_config.get(
            "exposure_password_field", "password"
        )
        self.password_mask: str = client.scan_config.get(
            "exposure_password_mask", "********************************"
        )

    def run(self) -> list[VulnerabilityResult]:
        self._fresh_synthetic_login("requester")
        return [
            self._test_exposure(),
            self._test_unauthenticated_rejected(),
        ]

    def _fresh_synthetic_login(self, role: str) -> None:
        """Mirrors authorization.py's `_fresh_synthetic_juiceshop_login` —
        Juice Shop has no reseed endpoint reachable mid-session and a
        duplicate email 400s (see src/utils/juiceshop_client.py), so each
        run needs its own fresh identity.
        """
        user = self.client.test_users[role]
        suffix = uuid.uuid4().hex[:10]
        user["email"] = f"{role}.{suffix}@juiceshop-test.local"
        self.client.register(role)
        self.client.login(role)

    def _test_exposure(self) -> VulnerabilityResult:
        resp = self.client.get_user_exposure(as_user="requester")
        path = self.client.endpoints.get(
            "user_exposure", "/rest/user/authentication-details"
        )

        if resp.status_code != 200:
            return self._result(
                passed=True,
                severity=Severity.LOW,
                evidence=(
                    f"GET {path} as an ordinary authenticated user returned "
                    f"HTTP {resp.status_code}, not 200 — inconclusive, not itself a finding."
                ),
                request_summary=f"GET {path} as_user='requester'",
                response_summary=f"HTTP {resp.status_code}",
            )

        try:
            body = resp.json()
        except ValueError:
            return self._result(
                passed=True,
                severity=Severity.LOW,
                evidence=f"GET {path} returned HTTP 200 but non-JSON body — inconclusive.",
                request_summary=f"GET {path} as_user='requester'",
                response_summary="HTTP 200; non-JSON body",
            )

        own_email = self.client.test_users["requester"]["email"]
        records = body.get("data", [])
        if not isinstance(records, list):
            records = []

        other_emails = [
            r.get(self.email_field)
            for r in records
            if isinstance(r, dict) and r.get(self.email_field) not in (None, own_email)
        ]
        unmasked_passwords = [
            r.get(self.email_field)
            for r in records
            if isinstance(r, dict)
            and r.get(self.password_field) not in (None, self.password_mask)
        ]

        leaked = bool(other_emails) or bool(unmasked_passwords)
        evidence = (
            f"GET {path} as an ordinary, non-admin authenticated user -> HTTP 200 with "
            f"{len(records)} user record(s) in the response body."
        )
        if other_emails:
            evidence += (
                f" Contains {len(other_emails)} other account(s)' email addresses "
                f"(e.g. {other_emails[0]!r}), which this requester has no legitimate "
                "reason to see."
            )
        if unmasked_passwords:
            evidence += (
                f" {len(unmasked_passwords)} record(s) have a '{self.password_field}' "
                f"field that is NOT the known masked placeholder "
                f"({self.password_mask!r}) — a real-looking value is present."
            )
        else:
            evidence += (
                f" The '{self.password_field}' field is masked to a constant "
                f"placeholder ({self.password_mask!r}) for every record, not a real hash."
            )

        return self._result(
            passed=not leaked,
            severity=Severity.HIGH if leaked else Severity.LOW,
            evidence=evidence,
            request_summary=f"GET {path} as_user='requester'",
            response_summary=(
                f"HTTP 200; records={len(records)}; other_emails_leaked={len(other_emails)}; "
                f"unmasked_passwords={len(unmasked_passwords)}"
            ),
            other_emails_sample=other_emails[:3],
        )

    def _test_unauthenticated_rejected(self) -> VulnerabilityResult:
        resp = self.client.get_user_exposure(as_user=None)
        path = self.client.endpoints.get(
            "user_exposure", "/rest/user/authentication-details"
        )
        rejected = resp.status_code == 401

        evidence = f"Unauthenticated request to GET {path} -> HTTP {resp.status_code}."
        if rejected:
            evidence += (
                " Rejected, as expected — authentication is enforced here; the "
                "exposure finding above is about excessive data returned to an "
                "authenticated, non-privileged user, not a missing auth check."
            )
        else:
            evidence += " NOT rejected — this endpoint has no authentication check at all."

        return self._result(
            passed=rejected,
            severity=Severity.LOW if rejected else Severity.HIGH,
            evidence=evidence,
            request_summary=f"GET {path} as_user=None",
            response_summary=f"HTTP {resp.status_code}",
        )


def _print_results(results: list[VulnerabilityResult]) -> None:
    for result in results:
        status = "PASS" if result.passed else f"FAIL ({result.severity.value.upper()})"
        print(f"[{status}] {result.test_name} - {result.owasp_category}")
        print(f"  Evidence:  {result.evidence}")
        print(f"  Request:   {result.request_summary}")
        print(f"  Response:  {result.response_summary}")
        print()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    client = JuiceShopClient.from_config("config/juiceshop.yaml")
    with RunLogger("rest", "juiceshop", "config/juiceshop.yaml") as run:
        results = ExcessiveUserDataExposureTest(
            architecture="rest", target="juiceshop", client=client
        ).run()
        run.log_results(results)
    _print_results(results)
