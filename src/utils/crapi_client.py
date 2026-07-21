from __future__ import annotations

import logging
import re
import time
from typing import Any, Optional

import requests

from src.utils.api_client import ConfigError, RESTAPIClient

logger = logging.getLogger(__name__)

# crAPI emails (a welcome mail) a new user their VIN and PIN as HTML font tags (raw format);
# MailHog (fake email server) stores the raw MIME source.
# These regex extract the two values from raw format.
_VIN_PATTERN = re.compile(r"VIN:\s*</font><font[^>]*>([A-Z0-9]+)")
_PINCODE_PATTERN = re.compile(r"Pincode:\s*<font[^>]*>(\d+)")


class CrAPIClient(RESTAPIClient):
    """RESTAPIClient subclass for crAPI's auth flow and coupon endpoints."""

    @property
    def scan_config(self) -> dict[str, Any]:
        return self._config.get("scan", {})

    def signup(self, role: str) -> requests.Response:
        """Register a test user identified by role."""
        user = self._require_user(role)
        path = self.endpoints.get("signup", "/identity/api/auth/signup")
        payload = {
            "name": user["name"],
            "email": user["email"],
            "password": user["password"],
            "number": user["number"],
        }
        resp = self.session.post(self._url(path), json=payload, timeout=self.timeout)
        logger.info("Signup '%s': %s -> %s", role, path, resp.status_code)
        return resp

    def login(self, role: str) -> str:
        """Log in a test user and store their token for later requests."""
        user = self._require_user(role)
        path = self.endpoints.get("login", "/identity/api/auth/login")
        payload = {"email": user["email"], "password": user["password"]}
        resp = self.session.post(self._url(path), json=payload, timeout=self.timeout)
        resp.raise_for_status()

        data = resp.json()
        token = data.get("token")
        if not token:
            raise RuntimeError(
                f"Login response for '{role}' did not contain a token: {data}"
            )

        self._tokens[role] = token
        logger.info("Login '%s': token stored", role)
        return token

    def validate_coupon(
        self, body: dict[str, Any], as_user: Optional[str]
    ) -> requests.Response:
        """POST to the NoSQL-injectable validate-coupon endpoint."""
        path = self.endpoints.get(
            "validate_coupon", "/community/api/v2/coupon/validate-coupon"
        )
        resp = self.session.post(
            self._url(path),
            json=body,
            headers=self._headers_for(as_user),
            timeout=self.timeout,
        )
        return resp

    def apply_coupon(
        self, coupon_code: str, amount: int, as_user: Optional[str]
    ) -> requests.Response:
        """POST to the SQL-injectable apply_coupon endpoint."""
        path = self.endpoints.get("apply_coupon", "/workshop/api/shop/apply_coupon")
        resp = self.session.post(
            self._url(path),
            json={"coupon_code": coupon_code, "amount": amount},
            headers=self._headers_for(as_user),
            timeout=self.timeout,
        )
        return resp

    def add_vehicle(
        self, vin: str, pincode: str, as_user: Optional[str]
    ) -> requests.Response:
        """Registers a vehicle (by VIN + pincode) to the calling account."""
        path = self.endpoints.get("add_vehicle", "/identity/api/v2/vehicle/add_vehicle")
        resp = self.session.post(
            self._url(path),
            json={"vin": vin, "pincode": pincode},
            headers=self._headers_for(as_user),
            timeout=self.timeout,
        )
        return resp

    def list_vehicles(self, as_user: Optional[str]) -> requests.Response:
        """Lists vehicles registered to the calling account."""
        path = self.endpoints.get("vehicles", "/identity/api/v2/vehicle/vehicles")
        return self.session.get(
            self._url(path), headers=self._headers_for(as_user), timeout=self.timeout
        )

    def get_vehicle_location(
        self, vehicle_id: str, as_user: Optional[str]
    ) -> requests.Response:
        """Fetches a vehicle's GPS location and owner details by vehicle id."""
        template = self.endpoints.get(
            "vehicle_location", "/identity/api/v2/vehicle/{vehicle_id}/location"
        )
        path = template.format(vehicle_id=vehicle_id)
        return self.session.get(
            self._url(path), headers=self._headers_for(as_user), timeout=self.timeout
        )

    def create_order(
        self, product_id: int, quantity: int, as_user: Optional[str]
    ) -> requests.Response:
        """Places a shop order for the calling account."""
        path = self.endpoints.get("create_order", "/workshop/api/shop/orders")
        return self.session.post(
            self._url(path),
            json={"product_id": product_id, "quantity": quantity},
            headers=self._headers_for(as_user),
            timeout=self.timeout,
        )

    def get_order(self, order_id: int, as_user: Optional[str]) -> requests.Response:
        """
        Fetches a single order's detail by order id.
        """
        template = self.endpoints.get(
            "order_detail", "/workshop/api/shop/orders/{order_id}"
        )
        path = template.format(order_id=order_id)
        return self.session.get(
            self._url(path), headers=self._headers_for(as_user), timeout=self.timeout
        )

    def list_orders(self, as_user: Optional[str]) -> requests.Response:
        """Lists orders belonging to the calling account."""
        path = self.endpoints.get("orders_all", "/workshop/api/shop/orders/all")
        return self.session.get(
            self._url(path), headers=self._headers_for(as_user), timeout=self.timeout
        )

    def fetch_welcome_credentials(
        self, email: str, max_attempts: int = 5, poll_interval: float = 1.0
    ) -> Optional[tuple[str, str]]:
        """
        Retrieves the VIN and pincode crAPI emails a new account on signup,
        via the MailHog instance in the crAPI docker-compose stack.

        The email is not immediately available in MailHog after signup is done —
        there is a short delay. The function checks MailHog, and if the email
        is not yet there, waits `poll_interval` seconds and checks again, up to 
        `max_attempts` times, before giving up and returning None.

        Vehicle Identification Number (VIN) and Pincode pair are used as
        vehicle-claim credential pair for an owner.
        """
        mailhog_url = self._config.get("target", {}).get(
            "mailhog_base_url", "http://127.0.0.1:8025"
        )
        search_url = f"{mailhog_url}/api/v2/search"
        for _ in range(max_attempts):
            resp = self.session.get(
                search_url,
                params={"kind": "to", "query": email},
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                items = resp.json().get("items", [])
                if items:
                    raw = items[0]["Raw"]["Data"]
                    vin_match = _VIN_PATTERN.search(raw)
                    pin_match = _PINCODE_PATTERN.search(raw)
                    if vin_match and pin_match:
                        return vin_match.group(1), pin_match.group(1)
            time.sleep(poll_interval)
        return None

    def _require_user(self, role: str) -> dict[str, str]:
        """Fetch a role's credentials from config, and raise errors if it is missing"""
        user = self.test_users.get(role)
        if not user:
            raise ConfigError(
                f"No test user configured for role '{role}' in config file"
            )
        return user
