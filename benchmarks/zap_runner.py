"""
OWASP ZAP benchmark runner for the REST targets.
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from typing import Any, Optional

import requests
import yaml
from zapv2 import ZAPv2

from src.analysis.comparative_stats import load_benchmark_mapping
from src.utils.results_logger import RunLogger
from src.utils.vampi_client import VAmPIClient
from src.vulnerabilities.base import (
    Severity,
    VulnerabilityResult,
    ResultSource,
)

logger = logging.getLogger(__name__)

INTERNAL_TARGET_BASE_URL = {
    "vampi": "http://vampi:5000",
    "crapi": "http://crapi-web:80",
    "juiceshop": "http://juiceshop:3000",
}

SPIDER_POLL_INTERVAL_SECONDS = 2.0
SPIDER_MAX_WAIT_SECONDS = 120.0
ASCAN_POLL_INTERVAL_SECONDS = 2.0
ASCAN_MAX_WAIT_SECONDS = 180.0

RISK_ORDER = ["High", "Medium", "Low", "Informational"]
RISK_TO_SEVERITY = {
    "High": Severity.CRITICAL,
    "Medium": Severity.HIGH,
    "Low": Severity.MEDIUM,
    "Informational": Severity.LOW,
}

TARGET_QUERYSTRING = 1
TARGET_POSTDATA = 2
TARGET_COOKIE = 4
TARGET_HTTPHEADERS = 8
TARGET_URLPATH = 16
TARGET_PLAINBODY = 32
TARGET_INJECTABLE_DEFAULT = 35

PATH_SEGMENT_DEPENDENT_TEST_NAMES = {"sqli_user_lookup"}

ALERT_NAME_HINTS: dict[str, Optional[tuple[str, ...]]] = {
    "sqli_user_lookup": ("sql injection",),
    "sqli_apply_coupon": ("sql injection",),
    "nosqli_coupon_validate": None,
    "jwt_weak_signing_bypass": None,
    "jwt_signature_verification_bypass": None,
    "vampi_debug_endpoint_exposure": None,
    "excessive_user_data_exposure": None,
    "bola_basket_access": None,
}

POST_BODY_BY_TEST_NAME: dict[str, dict[str, Any]] = {
    "nosqli_coupon_validate": {"coupon_code": "TEST10"},
    "sqli_apply_coupon": {"coupon_code": "TEST10", "amount": 1},
}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _load_zap_connection(app: str) -> dict[str, Any]:
    """Reads ZAP's host, port, and API key from config/<app>.yaml"""
    with open(f"config/{app}.yaml", "r") as f:
        data = yaml.safe_load(f)
    zap_config = data.get("zap")
    if not zap_config:
        raise RuntimeError(
            f"config/{app}.yaml has no 'zap:' block -- add one matching "
            "docker/docker-compose.zap.yml's zap-{app} service before "
            "benchmarking this target."
        )
    return zap_config


def _connect(zap_config: dict[str, Any]) -> tuple[ZAPv2, bool]:
    """
    Connects to the ZAP daemon and enables URL-path-segment injection
    (`sqli_user_lookup` test case is injectable only through the URL path).
    """
    proxy = f"http://{zap_config['host']}:{zap_config['port']}"
    zap = ZAPv2(apikey=zap_config["api_key"], proxies={"http": proxy, "https": proxy})

    desired = TARGET_INJECTABLE_DEFAULT | TARGET_URLPATH
    zap.ascan.set_option_target_params_injectable(desired)
    actual = int(zap.ascan.option_target_params_injectable)
    path_injection_confirmed = bool(actual & TARGET_URLPATH)

    status = "ENABLED" if path_injection_confirmed else "NOT ENABLED"
    logger.info(
        "ZAP ascan target_params_injectable: requested=%s actual=%s "
        "(URL path segment injection %s)",
        desired,
        actual,
        status,
    )
    print(
        f"[zap config] target_params_injectable={actual} (URL path segment injection {status})"
    )

    return zap, path_injection_confirmed


def _resolve_vampi_book_title(host_base_url: Optional[str]) -> Optional[str]:
    """
    Fetches a book title as a `/books/v1/{book_title}` test needs
    a real book title for ZAP's active scan to probe a resource.
    """
    if host_base_url is None:
        return None
    try:
        resp = requests.get(f"{host_base_url}/books/v1", timeout=10)
    except requests.exceptions.RequestException:
        return None
    if resp.status_code != 200:
        return None
    try:
        books = resp.json().get("Books", [])
    except ValueError:
        return None
    if not books or not isinstance(books, list):
        return None
    return books[0].get("book_title")


def _resolve_endpoint_placeholders(
    endpoint: str, internal_base_url: str, host_base_url: Optional[str]
) -> Optional[str]:
    """Resolves every `{...}` path template in `endpoint` to a concrete value."""
    if "{book_title}" in endpoint:
        book_title = _resolve_vampi_book_title(host_base_url)
        if book_title is None:
            return None
        endpoint = endpoint.format(book_title=book_title)
    if "{id}" in endpoint:
        endpoint = endpoint.format(id=1)
    return endpoint


def _poll_until_complete(
    status_fn: Any,
    scan_id: Any,
    poll_interval: float,
    max_wait: float,
    stage_name: str,
) -> tuple[str, Optional[str]]:
    """Repeatedly checks if the scan has been done using a timeout."""
    deadline = time.monotonic() + max_wait
    while True:
        status = status_fn(scan_id)
        try:
            progress = int(status)
        except (TypeError, ValueError):
            return "rejected", (
                f"{stage_name} scan was rejected by ZAP (scan id {scan_id!r}, "
                f"status={status!r}) -- likely a malformed or unreachable "
                "target URL; no alerts were collected."
            )
        if progress >= 100:
            return "ok", None
        if time.monotonic() > deadline:
            return "timeout", (
                f"{stage_name} scan did not reach 100% within {max_wait}s -- "
                "alerts reflect a partial scan."
            )
        time.sleep(poll_interval)


def _build_raw_post_request(url: str, json_body: dict[str, Any]) -> str:
    """Builds a raw HTTP request for POST-based tests."""
    body = json.dumps(json_body)
    body_bytes = body.encode("utf-8")
    return (
        f"POST {url} HTTP/1.1\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        "\r\n"
        f"{body}"
    )


def _scan_target(
    zap: ZAPv2,
    url: str,
    method: str = "GET",
    json_body: Optional[dict[str, Any]] = None,
) -> tuple[list[dict[str, Any]], list[str], bool]:
    """Orchestrates spider -> active scan -> alert collection for one URL"""
    caveats: list[str] = []
    if method == "POST":
        zap.core.send_request(_build_raw_post_request(url, json_body or {}))
    else:
        zap.core.access_url(url)

    spider_id = zap.spider.scan(url)
    outcome, caveat = _poll_until_complete(
        zap.spider.status,
        spider_id,
        SPIDER_POLL_INTERVAL_SECONDS,
        SPIDER_MAX_WAIT_SECONDS,
        "Spider",
    )
    if caveat:
        caveats.append(caveat)
    if outcome == "rejected":
        return [], caveats, True

    ascan_id = zap.ascan.scan(url)
    outcome, caveat = _poll_until_complete(
        zap.ascan.status,
        ascan_id,
        ASCAN_POLL_INTERVAL_SECONDS,
        ASCAN_MAX_WAIT_SECONDS,
        "Active",
    )
    if caveat:
        caveats.append(caveat)
    if outcome == "rejected":
        return [], caveats, True

    alerts = zap.core.alerts(baseurl=url)
    return alerts, caveats, False


def _path_injection_caveat(test_name: str, path_injection_confirmed: bool) -> str:
    """Adds a warning if path scanning is not confirmed enabled."""
    if test_name not in PATH_SEGMENT_DEPENDENT_TEST_NAMES:
        return ""
    if path_injection_confirmed:
        return (
            " ZAP's active scan was confirmed configured to inject into URL "
            "path segments (target_params_injectable includes TARGET_URLPATH), "
            "matching this endpoint's actual injection point."
        )
    return (
        " CAVEAT: ZAP's active scan target_params_injectable option does not "
        "include URL path segments (TARGET_URLPATH) -- path-segment injection "
        "coverage for this endpoint is unconfirmed, so a clean result here may "
        "mean 'ZAP never tried this vector' rather than 'ZAP tried and found "
        "nothing'."
    )


def _result_from_scan(
    test_name: str,
    owasp_category: str,
    app: str,
    url: str,
    alerts: list[dict[str, Any]],
    caveats: list[str],
    requires_auth: bool,
    rejected: bool,
    path_injection_confirmed: bool,
    method: str = "GET",
) -> VulnerabilityResult:
    """
    Takes ZAP's raw alerts and converts them into standard 
    VulnerabilityResult object (pass/fail, severity, evidence text).
    """
    request_summary = (
        f"ZAP spider + active scan: {method} {url}"
        if method == "POST"
        else f"ZAP spider + active scan: {url}"
    )

    if rejected:
        evidence = f"ZAP rejected the scan request for {url} outright -- no alerts were collected."
        for caveat in caveats:
            evidence += f" {caveat}"
        return VulnerabilityResult(
            test_name=test_name,
            owasp_category=owasp_category,
            architecture="rest",
            target=app,
            passed=True,
            severity=Severity.LOW,
            evidence=evidence,
            request_summary=request_summary,
            response_summary="scan rejected by ZAP; no alerts collected",
            source=ResultSource.ZAP,
            extra={"inconclusive": True},
        )

    hints = ALERT_NAME_HINTS.get(test_name)
    all_alert_names = (
        ", ".join(sorted({a.get("alert", "unnamed alert") for a in alerts})) or "none"
    )

    if hints is None:
        evidence = (
            f"ZAP scan of {url} completed with {len(alerts)} total alert(s) of "
            f"any kind ({all_alert_names}), but ZAP has no active-scan rule "
            f"type capable of detecting '{test_name}' at all -- this is a gap "
            "in ZAP's own rule coverage, not zero matches from an attempted "
            "detection."
        )
        if requires_auth:
            evidence += (
                " Also scanned with no authenticated session, compounding why "
                "this couldn't be tested even if a matching rule existed."
            )
        for caveat in caveats:
            evidence += f" {caveat}"
        return VulnerabilityResult(
            test_name=test_name,
            owasp_category=owasp_category,
            architecture="rest",
            target=app,
            passed=True,
            severity=Severity.LOW,
            evidence=evidence,
            request_summary=request_summary,
            response_summary=f"{len(alerts)} alert(s); none applicable to this test case",
            source=ResultSource.ZAP,
        )

    matched = [
        a for a in alerts if any(hint in a.get("alert", "").lower() for hint in hints)
    ]
    vulnerable = bool(matched)
    alert_risks = {a.get("risk", "Informational") for a in matched}
    highest_risk = next(
        (risk for risk in RISK_ORDER if risk in alert_risks), "Informational"
    )
    matched_alert_names = (
        ", ".join(sorted({a.get("alert", "unnamed alert") for a in matched})) or "none"
    )

    evidence = (
        f"ZAP scan of {url} -> {len(alerts)} total alert(s) ({all_alert_names}); "
        f"{len(matched)} matched this test case's alert type(s) "
        f"({matched_alert_names})."
    )
    if requires_auth:
        evidence += (
            " Scanned with no authenticated session -- ZAP's spider/active "
            "scan does not itself log in, so this result reflects only what "
            "an unauthenticated crawl could reach, not the ownership/logic "
            "bypass this framework's own module confirms."
        )
    evidence += _path_injection_caveat(test_name, path_injection_confirmed)
    for caveat in caveats:
        evidence += f" {caveat}"

    return VulnerabilityResult(
        test_name=test_name,
        owasp_category=owasp_category,
        architecture="rest",
        target=app,
        passed=not vulnerable,
        severity=RISK_TO_SEVERITY[highest_risk] if vulnerable else Severity.LOW,
        evidence=evidence,
        request_summary=request_summary,
        response_summary=(
            f"{len(matched)}/{len(alerts)} matched alert(s); "
            f"highest_risk={highest_risk if vulnerable else 'n/a'}"
        ),
        source=ResultSource.ZAP,
    )


def _run_entry(
    zap: ZAPv2,
    entry: dict[str, Any],
    path_injection_confirmed: bool,
    host_base_url: Optional[str],
) -> list[VulnerabilityResult]:
    """Runs all test cases for a benchmark mapping entry."""
    app = entry["app"]
    internal_base_url = INTERNAL_TARGET_BASE_URL[app]

    test_names = _as_list(entry["framework_test_name"])
    categories = _as_list(entry["owasp_category"])
    targets = _as_list(entry["target"])

    results: list[VulnerabilityResult] = []
    for test_name, category, target_spec in zip(test_names, categories, targets):
        endpoint = _resolve_endpoint_placeholders(
            target_spec["endpoint"], internal_base_url, host_base_url
        )
        if endpoint is None:
            results.append(
                VulnerabilityResult(
                    test_name=test_name,
                    owasp_category=category,
                    architecture="rest",
                    target=app,
                    passed=True,
                    severity=Severity.LOW,
                    evidence=(
                        f"Could not resolve {target_spec['endpoint']!r}'s path "
                        "placeholder(s) to build a concrete scan URL -- "
                        "inconclusive setup step, not itself a ZAP finding."
                    ),
                    source=ResultSource.ZAP,
                    extra={"inconclusive": True},
                )
            )
            continue

        url = f"{internal_base_url}{endpoint}"
        method = target_spec.get("method", "GET")
        json_body = POST_BODY_BY_TEST_NAME.get(test_name) if method == "POST" else None
        alerts, caveats, rejected = _scan_target(
            zap, url, method=method, json_body=json_body
        )
        results.append(
            _result_from_scan(
                test_name=test_name,
                owasp_category=category,
                app=app,
                url=url,
                alerts=alerts,
                caveats=caveats,
                requires_auth=bool(target_spec.get("requires_auth")),
                rejected=rejected,
                path_injection_confirmed=path_injection_confirmed,
                method=method,
            )
        )
    return results


def _print_results(results: list[VulnerabilityResult]) -> None:
    for result in results:
        status = "PASS" if result.passed else f"FAIL ({result.severity.value.upper()})"
        print(f"[{status}] {result.test_name} - {result.owasp_category} (ZAP)")
        print(f"  Evidence:  {result.evidence}")
        print(f"  Request:   {result.request_summary}")
        print(f"  Response:  {result.response_summary}")
        print()


def _run_app(app: str) -> None:
    zap_config = _load_zap_connection(app)
    zap, path_injection_confirmed = _connect(zap_config)

    host_base_url: Optional[str] = None
    if app == "vampi":
        vampi_client = VAmPIClient.from_config("config/vampi.yaml")
        host_base_url = vampi_client.base_url
        reseed_resp = vampi_client.seed_database()
        logger.info(
            "VAmPI /createdb reseed before ZAP benchmark: %s", reseed_resp.status_code
        )
        print(f"[vampi reseed] /createdb -> {reseed_resp.status_code}")

    entries = [
        e for e in load_benchmark_mapping() if e["tool"] == "zap" and e["app"] == app
    ]
    if not entries:
        logger.info("No 'tool: zap' benchmark_mapping.yaml entries for '%s'", app)
        return

    with RunLogger("rest", app, f"config/{app}.yaml") as run:
        all_results: list[VulnerabilityResult] = []
        for entry in entries:
            entry_results = _run_entry(
                zap, entry, path_injection_confirmed, host_base_url
            )
            run.log_results(entry_results)
            all_results.extend(entry_results)
    _print_results(all_results)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        choices=["vampi", "crapi", "juiceshop", "all"],
        default="all",
        help=(
            "Which target's stack and matching zap-<target> daemon must be "
            "up (see docker/docker-compose.zap.yml). Default 'all' requires "
            "every REST target's stack and ZAP daemon running -- pass "
            "--target to benchmark just one."
        ),
    )
    args = parser.parse_args()

    apps = ["vampi", "crapi", "juiceshop"] if args.target == "all" else [args.target]
    for target_app in apps:
        _run_app(target_app)
