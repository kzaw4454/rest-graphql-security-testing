"""
Broken Object Level Authorization (BOLA / OWASP API1:2023) tests against VAmPI.

API1:2023 is the OWASP API Security Top 10 category for APIs that expose
object identifiers (here, a book title) without verifying that the
requesting user actually owns the referenced object. It is consistently
ranked as the most prevalent API vulnerability in industry surveys (see
ProposalReport.docx §2), and VAmPI's own OpenAPI spec documents
`GET /books/v1/{book_title}` as "Only the owner may retrieve it" while the
running container (vulnerable=1) does not actually enforce that check —
any authenticated user's token can retrieve another user's secret. This
module reproduces that finding so it is comparable, via the common
VulnerabilityResult schema, against the equivalent GraphQL BOLA tests run
against DVGA (see CLAUDE.md, §3.4/§3.5 methodology).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from src.utils.api_client import APIClient
from src.vulnerabilities.base import Severity, VulnerabilityResult, VulnerabilityTest

logger = logging.getLogger(__name__)

BOOKS_PATH = "/books/v1"


class BOLABookAccessTest(VulnerabilityTest):
    """
    Confirms whether VAmPI enforces object-level ownership on book secrets.

    Scenario: two independent users each create a book with a private
    `secret`. A confirmed BOLA exists if either user's own valid token can
    retrieve the *other* user's secret via `GET /books/v1/{book_title}` —
    the endpoint only checks that a token is valid, not that its owner
    matches the book's owner.
    """

    name = "bola_book_secret_access"
    owasp_category = "API1:2023 Broken Object Level Authorization"

    def __init__(self, architecture: str, target: str, client: APIClient) -> None:
        super().__init__(architecture, target)
        self.client = client

    def run(self) -> list[VulnerabilityResult]:
        self.client.seed_database()
        for role in ("victim", "attacker"):
            self.client.register(role)
            self.client.login(role)

        run_id = uuid.uuid4().hex[:8]
        victim_book = f"victimBook_{run_id}"
        victim_secret = f"victim-secret-{run_id}"
        attacker_book = f"attackerBook_{run_id}"
        attacker_secret = f"attacker-secret-{run_id}"

        self._create_book("victim", victim_book, victim_secret)
        self._create_book("attacker", attacker_book, attacker_secret)

        results = [
            self._test_cross_user_access(
                owner_role="victim",
                owner_book=victim_book,
                owner_secret=victim_secret,
                requester_role="attacker",
            ),
            self._test_cross_user_access(
                owner_role="attacker",
                owner_book=attacker_book,
                owner_secret=attacker_secret,
                requester_role="victim",
            ),
            self._test_unauthenticated_access(
                owner_book=victim_book, owner_secret=victim_secret
            ),
        ]
        return results

    def _create_book(self, role: str, book_title: str, secret: str) -> None:
        resp = self.client.post(
            BOOKS_PATH, as_user=role, json={"book_title": book_title, "secret": secret}
        )
        logger.info("Create book as '%s': %s -> %s", role, book_title, resp.status_code)

    def _test_cross_user_access(
        self,
        owner_role: str,
        owner_book: str,
        owner_secret: str,
        requester_role: str,
    ) -> VulnerabilityResult:
        """One book, one owner, one *other* authenticated user's token."""
        path = f"{BOOKS_PATH}/{owner_book}"
        resp = self.client.get(path, as_user=requester_role)
        leaked_secret = self._response_reveals_secret(resp, owner_secret)

        passed = not leaked_secret
        severity = Severity.HIGH if leaked_secret else Severity.LOW
        evidence = (
            f"Book '{owner_book}' owned by '{owner_role}' was "
            f"{'successfully retrieved' if leaked_secret else 'not retrieved'} "
            f"using '{requester_role}''s own valid token "
            f"(HTTP {resp.status_code})."
        )
        if leaked_secret:
            evidence += " Response contained the owner's secret, confirming BOLA."

        return self._result(
            passed=passed,
            severity=severity,
            evidence=evidence,
            request_summary=f"GET {path} as_user='{requester_role}'",
            response_summary=f"HTTP {resp.status_code}; secret_leaked={leaked_secret}",
            owner_role=owner_role,
            requester_role=requester_role,
            book_title=owner_book,
        )

    def _test_unauthenticated_access(
        self, owner_book: str, owner_secret: str
    ) -> VulnerabilityResult:
        """Control case: same object, no token at all. Documents whether the
        endpoint enforces authentication in addition to (not) enforcing
        ownership — useful context for the results table but not itself the
        BOLA finding.
        """
        path = f"{BOOKS_PATH}/{owner_book}"
        resp = self.client.get(path)
        leaked_secret = self._response_reveals_secret(resp, owner_secret)

        passed = not leaked_secret
        severity = Severity.CRITICAL if leaked_secret else Severity.LOW
        evidence = (
            f"Unauthenticated request for book '{owner_book}' "
            f"{'succeeded' if leaked_secret else 'was denied'} "
            f"(HTTP {resp.status_code})."
        )

        return self._result(
            passed=passed,
            severity=severity,
            evidence=evidence,
            request_summary=f"GET {path} as_user=None",
            response_summary=f"HTTP {resp.status_code}; secret_leaked={leaked_secret}",
            owner_role="victim",
            requester_role="unauthenticated",
            book_title=owner_book,
        )

    @staticmethod
    def _response_reveals_secret(resp: Any, expected_secret: str) -> bool:
        if resp.status_code != 200:
            return False
        try:
            body = resp.json()
        except ValueError:
            return False
        return body.get("secret") == expected_secret


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    client = APIClient.from_config("config/vampi.yaml")
    test = BOLABookAccessTest(architecture="rest", target="vampi", client=client)

    for result in test.run():
        status = "PASS" if result.passed else f"FAIL ({result.severity.value.upper()})"
        print(f"[{status}] {result.test_name} - {result.owasp_category}")
        print(f"  Evidence:  {result.evidence}")
        print(f"  Request:   {result.request_summary}")
        print(f"  Response:  {result.response_summary}")
        print()
