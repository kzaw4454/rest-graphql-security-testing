"""
Broken Object Level Authorization (BOLA / OWASP API1:2023) tests.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from src.utils.juiceshop_client import JuiceShopClient
from src.utils.vampi_client import VAmPIClient
from src.vulnerabilities.base import Severity, VulnerabilityResult, VulnerabilityTest

logger = logging.getLogger(__name__)

BOOKS_PATH = "/books/v1"


class BOLABookAccessTest(VulnerabilityTest):
    """
    Confirms whether VAmPI enforces object-level ownership on book secrets.
    """

    name = "bola_book_secret_access"
    owasp_category = "API1:2023 Broken Object Level Authorization"

    def __init__(self, architecture: str, target: str, client: VAmPIClient) -> None:
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


def _fresh_synthetic_juiceshop_login(client: JuiceShopClient, role: str) -> None:
    """Sign up and log in a brand-new synthetic identity for `role`.
    """
    user = client.test_users[role]
    suffix = uuid.uuid4().hex[:10]
    user["email"] = f"{role}.{suffix}@juiceshop-test.local"
    client.register(role)
    client.login(role)


class BOLABasketAccessTest(VulnerabilityTest):
    """
    Confirms whether Juice Shop enforces object-level ownership on baskets.
    """

    name = "bola_basket_access"
    owasp_category = "API1:2023 Broken Object Level Authorization"

    def __init__(self, architecture: str, target: str, client: JuiceShopClient) -> None:
        super().__init__(architecture, target)
        self.client = client

    def run(self) -> list[VulnerabilityResult]:
        for role in ("victim", "attacker"):
            _fresh_synthetic_juiceshop_login(self.client, role)

        victim_bid = self.client.basket_id_for("victim")
        attacker_bid = self.client.basket_id_for("attacker")

        return [
            self._test_cross_user_access(
                owner_role="victim", owner_bid=victim_bid, requester_role="attacker"
            ),
            self._test_cross_user_access(
                owner_role="attacker", owner_bid=attacker_bid, requester_role="victim"
            ),
            self._test_unauthenticated_access(owner_bid=victim_bid),
        ]

    def _test_cross_user_access(
        self, owner_role: str, owner_bid: int, requester_role: str
    ) -> VulnerabilityResult:
        """One basket, one owner, one *other* authenticated user's token."""
        resp = self.client.get_basket(owner_bid, as_user=requester_role)
        leaked = self._response_reveals_basket(resp, owner_bid)

        passed = not leaked
        severity = Severity.HIGH if leaked else Severity.LOW
        evidence = (
            f"Basket {owner_bid} owned by '{owner_role}' was "
            f"{'successfully retrieved' if leaked else 'not retrieved'} "
            f"using '{requester_role}''s own valid token "
            f"(HTTP {resp.status_code})."
        )
        if leaked:
            evidence += " Response contained the owner's basket contents, confirming BOLA."

        path = self.client.endpoints.get("basket", "/rest/basket/{id}").format(id=owner_bid)
        return self._result(
            passed=passed,
            severity=severity,
            evidence=evidence,
            request_summary=f"GET {path} as_user='{requester_role}'",
            response_summary=f"HTTP {resp.status_code}; basket_leaked={leaked}",
            owner_role=owner_role,
            requester_role=requester_role,
            basket_id=owner_bid,
        )

    def _test_unauthenticated_access(self, owner_bid: int) -> VulnerabilityResult:
        resp = self.client.get_basket(owner_bid, as_user=None)
        leaked = self._response_reveals_basket(resp, owner_bid)

        passed = not leaked
        severity = Severity.CRITICAL if leaked else Severity.LOW
        evidence = (
            f"Unauthenticated request for basket {owner_bid} "
            f"{'succeeded' if leaked else 'was denied'} "
            f"(HTTP {resp.status_code})."
        )

        path = self.client.endpoints.get("basket", "/rest/basket/{id}").format(id=owner_bid)
        return self._result(
            passed=passed,
            severity=severity,
            evidence=evidence,
            request_summary=f"GET {path} as_user=None",
            response_summary=f"HTTP {resp.status_code}; basket_leaked={leaked}",
            owner_role="victim",
            requester_role="unauthenticated",
            basket_id=owner_bid,
        )

    @staticmethod
    def _response_reveals_basket(resp: Any, expected_bid: int) -> bool:
        if resp.status_code != 200:
            return False
        try:
            body = resp.json()
        except ValueError:
            return False
        return body.get("data", {}).get("id") == expected_bid


def _print_results(results: list[VulnerabilityResult]) -> None:
    for result in results:
        status = "PASS" if result.passed else f"FAIL ({result.severity.value.upper()})"
        print(f"[{status}] {result.test_name} - {result.owasp_category}")
        print(f"  Evidence:  {result.evidence}")
        print(f"  Request:   {result.request_summary}")
        print(f"  Response:  {result.response_summary}")
        print()


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        choices=["vampi", "juiceshop", "all"],
        default="all",
        help=(
            "Which target's container must be up. Default 'all' requires both "
            "docker-compose.vampi.yml and docker-compose.juiceshop.yml to be running "
            "— pass --target to run just one."
        ),
    )
    args = parser.parse_args()

    if args.target in ("vampi", "all"):
        vampi_client = VAmPIClient.from_config("config/vampi.yaml")
        _print_results(
            BOLABookAccessTest(architecture="rest", target="vampi", client=vampi_client).run()
        )
    if args.target in ("juiceshop", "all"):
        juiceshop_client = JuiceShopClient.from_config("config/juiceshop.yaml")
        _print_results(
            BOLABasketAccessTest(
                architecture="rest", target="juiceshop", client=juiceshop_client
            ).run()
        )
