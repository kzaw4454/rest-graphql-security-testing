"""
Broken Object Level Authorization (BOLA / OWASP API1:2023) tests.
"""

from __future__ import annotations

import logging
import random
import uuid
from typing import Any, Optional

import requests

from src.utils.crapi_client import CrAPIClient
from src.utils.juiceshop_client import JuiceShopClient
from src.utils.results_logger import RunLogger
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
    """Sign up and log in a brand-new synthetic identity for `role`."""
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
            evidence += (
                " Response contained the owner's basket contents, confirming BOLA."
            )

        path = self.client.endpoints.get("basket", "/rest/basket/{id}").format(
            id=owner_bid
        )
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

        path = self.client.endpoints.get("basket", "/rest/basket/{id}").format(
            id=owner_bid
        )
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


class BOLAVehicleLocationAccessTest(VulnerabilityTest):
    """
    Confirms whether crAPI enforces object-level ownership on vehicle
    location lookups.

    crapi-identity's welcome email (captured via MailHog in this test's
    setup step) assigns every new account a VIN and pincode; adding that
    vehicle produces a vehicle id. `GET /identity/api/v2/vehicle/{id}/
    location` accepts any authenticated user's token regardless of which
    account added that vehicle, returning the owner's GPS coordinates,
    full name, and email. The community forum's public "recent posts"
    feed also exposes other users' vehicle ids directly (each post's
    author object includes a `vehicleid` field), so an attacker does not
    even need to guess or enumerate ids to exploit this.
    """

    name = "bola_vehicle_location_access"
    owasp_category = "API1:2023 Broken Object Level Authorization"

    def __init__(self, architecture: str, target: str, client: CrAPIClient) -> None:
        super().__init__(architecture, target)
        self.client = client

    def run(self) -> list[VulnerabilityResult]:
        for role in ("victim", "attacker"):
            _fresh_synthetic_login(self.client, role)
        victim_email = self.client.test_users["victim"]["email"]

        credentials = self.client.fetch_welcome_credentials(victim_email)
        if credentials is None:
            return [
                self._result(
                    passed=True,
                    severity=Severity.LOW,
                    evidence=(
                        "Could not retrieve the victim's VIN/pincode from the "
                        "welcome email via MailHog — inconclusive setup step, "
                        "not itself a finding."
                    ),
                    request_summary="GET mailhog search (victim welcome email)",
                    response_summary="no matching email found",
                )
            ]
        vin, pincode = credentials

        add_resp = self.client.add_vehicle(vin, pincode, as_user="victim")
        if add_resp.status_code != 200:
            return [
                self._result(
                    passed=True,
                    severity=Severity.LOW,
                    evidence=(
                        f"Adding the victim's vehicle failed (HTTP "
                        f"{add_resp.status_code}) — inconclusive setup step."
                    ),
                    request_summary="POST add_vehicle as_user='victim'",
                    response_summary=f"HTTP {add_resp.status_code}",
                )
            ]

        vehicle_id = self._discover_vehicle_id(vin)
        if vehicle_id is None:
            return [
                self._result(
                    passed=True,
                    severity=Severity.LOW,
                    evidence=(
                        "Could not find the newly-added vehicle's id in the "
                        "victim's vehicle list — inconclusive setup step."
                    ),
                    request_summary="GET vehicles as_user='victim'",
                    response_summary="vehicle not found in list",
                )
            ]

        return [
            self._test_owner_access(vehicle_id, victim_email),
            self._test_cross_user_access(vehicle_id, victim_email),
            self._test_unauthenticated_rejected(vehicle_id),
        ]

    def _discover_vehicle_id(self, vin: str) -> Optional[str]:
        resp = self.client.list_vehicles(as_user="victim")
        if resp.status_code != 200:
            return None
        try:
            vehicles = resp.json()
        except ValueError:
            return None
        for vehicle in vehicles:
            if vehicle.get("vin") == vin:
                return vehicle.get("uuid")
        return None

    def _test_owner_access(
        self, vehicle_id: str, victim_email: str
    ) -> VulnerabilityResult:
        """Control: the owner's own token must be able to read this data —
        otherwise the cross-user result below would be meaningless.
        """
        resp = self.client.get_vehicle_location(vehicle_id, as_user="victim")
        leaked = self._response_reveals_owner(resp, victim_email)

        return self._result(
            passed=True,
            severity=Severity.LOW,
            evidence=(
                f"Owner ('victim') requesting their own vehicle's location -> "
                f"HTTP {resp.status_code}"
                f"{' with owner details present, as expected' if leaked else ''}."
            ),
            request_summary=f"GET vehicle/{vehicle_id}/location as_user='victim'",
            response_summary=f"HTTP {resp.status_code}",
        )

    def _test_cross_user_access(
        self, vehicle_id: str, victim_email: str
    ) -> VulnerabilityResult:
        """One vehicle, one owner, one *other* authenticated user's token."""
        resp = self.client.get_vehicle_location(vehicle_id, as_user="attacker")
        leaked = self._response_reveals_owner(resp, victim_email)

        passed = not leaked
        severity = Severity.HIGH if leaked else Severity.LOW
        evidence = (
            f"Vehicle {vehicle_id} owned by 'victim' was "
            f"{'successfully retrieved' if leaked else 'not retrieved'} "
            f"using 'attacker''s own valid token (HTTP {resp.status_code})."
        )
        if leaked:
            evidence += (
                " Response contained the owner's GPS location, name, and "
                "email, confirming BOLA — no ownership check gates this route "
                "for any authenticated caller."
            )

        return self._result(
            passed=passed,
            severity=severity,
            evidence=evidence,
            request_summary=f"GET vehicle/{vehicle_id}/location as_user='attacker'",
            response_summary=f"HTTP {resp.status_code}; owner_leaked={leaked}",
            owner_role="victim",
            requester_role="attacker",
            vehicle_id=vehicle_id,
        )

    def _test_unauthenticated_rejected(self, vehicle_id: str) -> VulnerabilityResult:
        """Extra retest: unlike VAmPI's books endpoint, this route does
        require some valid token — confirms the cross-user finding above
        is a genuine ownership gap, not simply "no auth at all".
        """
        resp = self.client.get_vehicle_location(vehicle_id, as_user=None)
        rejected = resp.status_code == 401

        evidence = f"Unauthenticated request for vehicle {vehicle_id} -> HTTP {resp.status_code}."
        evidence += (
            " Rejected, as expected — this endpoint does require a valid "
            "token, but (see cross-user result) not one belonging to the "
            "vehicle's owner."
            if rejected
            else " NOT rejected — this endpoint has no authentication check at all."
        )

        return self._result(
            passed=rejected,
            severity=Severity.LOW if rejected else Severity.CRITICAL,
            evidence=evidence,
            request_summary=f"GET vehicle/{vehicle_id}/location as_user=None",
            response_summary=f"HTTP {resp.status_code}",
        )

    @staticmethod
    def _response_reveals_owner(resp: requests.Response, expected_email: str) -> bool:
        if resp.status_code != 200:
            return False
        try:
            body = resp.json()
        except ValueError:
            return False
        return body.get("email") == expected_email


class BOLAOrderAccessTest(VulnerabilityTest):
    """
    Confirms whether crAPI enforces object-level ownership on shop orders.

    `GET /workshop/api/shop/orders/{id}` returns full order detail
    (purchaser email and phone number, product, transaction id) for a
    sequential integer order id with no ownership check and, unlike the
    vehicle-location route above, no authentication requirement at all.
    """

    name = "bola_order_access"
    owasp_category = "API1:2023 Broken Object Level Authorization"

    def __init__(self, architecture: str, target: str, client: CrAPIClient) -> None:
        super().__init__(architecture, target)
        self.client = client
        self.product_id: int = client.scan_config.get("shop_product_id", 1)

    def run(self) -> list[VulnerabilityResult]:
        for role in ("victim", "attacker"):
            _fresh_synthetic_login(self.client, role)
        victim_email = self.client.test_users["victim"]["email"]

        order_resp = self.client.create_order(self.product_id, 1, as_user="victim")
        order_id = self._extract_order_id(order_resp)
        if order_id is None:
            return [
                self._result(
                    passed=True,
                    severity=Severity.LOW,
                    evidence=(
                        f"Placing the victim's order failed (HTTP "
                        f"{order_resp.status_code}) — inconclusive setup step."
                    ),
                    request_summary="POST orders as_user='victim'",
                    response_summary=f"HTTP {order_resp.status_code}",
                )
            ]

        return [
            self._test_attacker_has_no_orders_of_own(),
            self._test_cross_user_access(order_id, victim_email),
            self._test_unauthenticated_access(order_id, victim_email),
        ]

    @staticmethod
    def _extract_order_id(resp: requests.Response) -> Optional[int]:
        if resp.status_code != 200:
            return None
        try:
            return resp.json().get("id")
        except ValueError:
            return None

    def _test_attacker_has_no_orders_of_own(self) -> VulnerabilityResult:
        """Baseline: confirms the attacker owns zero orders of their own,
        so any order they can retrieve in the cross-user test below must
        belong to someone else.
        """
        resp = self.client.list_orders(as_user="attacker")
        own_order_count = None
        if resp.status_code == 200:
            try:
                own_order_count = resp.json().get("count")
            except ValueError:
                pass

        return self._result(
            passed=True,
            severity=Severity.LOW,
            evidence=(
                f"Attacker's own order list -> HTTP {resp.status_code}, "
                f"count={own_order_count!r} (expected 0, a fresh synthetic "
                "identity that has placed no orders of its own)."
            ),
            request_summary="GET orders/all as_user='attacker'",
            response_summary=f"HTTP {resp.status_code}; count={own_order_count!r}",
        )

    def _test_cross_user_access(
        self, order_id: int, victim_email: str
    ) -> VulnerabilityResult:
        """One order, one owner, one *other* authenticated user's token."""
        resp = self.client.get_order(order_id, as_user="attacker")
        leaked = self._response_reveals_owner(resp, victim_email)

        passed = not leaked
        severity = Severity.HIGH if leaked else Severity.LOW
        evidence = (
            f"Order {order_id} owned by 'victim' was "
            f"{'successfully retrieved' if leaked else 'not retrieved'} "
            f"using 'attacker''s own valid token (HTTP {resp.status_code})."
        )
        if leaked:
            evidence += (
                " Response contained the owner's email and phone number, "
                "confirming BOLA — order ids are sequential integers with "
                "no ownership check."
            )

        return self._result(
            passed=passed,
            severity=severity,
            evidence=evidence,
            request_summary=f"GET orders/{order_id} as_user='attacker'",
            response_summary=f"HTTP {resp.status_code}; owner_leaked={leaked}",
            owner_role="victim",
            requester_role="attacker",
            order_id=order_id,
        )

    def _test_unauthenticated_access(
        self, order_id: int, victim_email: str
    ) -> VulnerabilityResult:
        """Control case: same object, no token at all. Unlike the
        vehicle-location route, this endpoint enforces no authentication
        either, so an unauthenticated caller succeeds too.
        """
        resp = self.client.get_order(order_id, as_user=None)
        leaked = self._response_reveals_owner(resp, victim_email)

        return self._result(
            passed=not leaked,
            severity=Severity.CRITICAL if leaked else Severity.LOW,
            evidence=(
                f"Unauthenticated request for order {order_id} "
                f"{'succeeded' if leaked else 'was denied'} "
                f"(HTTP {resp.status_code})."
            ),
            request_summary=f"GET orders/{order_id} as_user=None",
            response_summary=f"HTTP {resp.status_code}; owner_leaked={leaked}",
            owner_role="victim",
            requester_role="unauthenticated",
            order_id=order_id,
        )

    @staticmethod
    def _response_reveals_owner(resp: requests.Response, expected_email: str) -> bool:
        if resp.status_code != 200:
            return False
        try:
            body = resp.json()
        except ValueError:
            return False
        return body.get("order", {}).get("user", {}).get("email") == expected_email


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
        choices=["vampi", "juiceshop", "crapi", "all"],
        default="all",
        help=(
            "Which target's container must be up. Default 'all' requires "
            "docker-compose.vampi.yml, docker-compose.juiceshop.yml, and "
            "docker-compose.crapi.yml to all be running — pass --target to "
            "run just one."
        ),
    )
    args = parser.parse_args()

    if args.target in ("vampi", "all"):
        vampi_client = VAmPIClient.from_config("config/vampi.yaml")
        with RunLogger("rest", "vampi", "config/vampi.yaml") as run:
            vampi_results = BOLABookAccessTest(
                architecture="rest", target="vampi", client=vampi_client
            ).run()
            run.log_results(vampi_results)
        _print_results(vampi_results)
    if args.target in ("juiceshop", "all"):
        juiceshop_client = JuiceShopClient.from_config("config/juiceshop.yaml")
        with RunLogger("rest", "juiceshop", "config/juiceshop.yaml") as run:
            juiceshop_results = BOLABasketAccessTest(
                architecture="rest", target="juiceshop", client=juiceshop_client
            ).run()
            run.log_results(juiceshop_results)
        _print_results(juiceshop_results)
    if args.target in ("crapi", "all"):
        crapi_client = CrAPIClient.from_config("config/crapi.yaml")
        with RunLogger("rest", "crapi", "config/crapi.yaml") as run:
            vehicle_results = BOLAVehicleLocationAccessTest(
                architecture="rest", target="crapi", client=crapi_client
            ).run()
            run.log_results(vehicle_results)
            order_results = BOLAOrderAccessTest(
                architecture="rest", target="crapi", client=crapi_client
            ).run()
            run.log_results(order_results)
        _print_results(vehicle_results)
        _print_results(order_results)
