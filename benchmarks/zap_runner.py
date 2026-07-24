"""
OWASP ZAP benchmark runner for the REST targets.

Drives a ZAP daemon (see docker/docker-compose.zap.yml) through the same
spider -> active scan -> alerts sequence for every config/benchmark_mapping.yaml
entry tagged `tool: zap`, and logs the outcome as VulnerabilityResult rows
(source=ZAP) via the same RunLogger every framework module uses. This lets
comparative_stats.py's benchmark_comparison() join ZAP's results against
this framework's own detection results for the dissertation's benchmarking
section.
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

# ZAP's daemon runs inside its own container on the target's docker network
# (docker/docker-compose.zap.yml), so it must address the target by its
# container hostname and the port that container listens on *internally* --
# not the host-published base_url each target's own config/<target>.yaml
# uses for this framework's own REST clients, which run on the host. See
# notes/notes_benchmarks/zap_runner.md.
INTERNAL_TARGET_BASE_URL = {
    "vampi": "http://vampi:5000",
    "crapi": "http://crapi-web:80",
    "juiceshop": "http://juiceshop:3000",
}

SPIDER_POLL_INTERVAL_SECONDS = 2.0
SPIDER_MAX_WAIT_SECONDS = 120.0
ASCAN_POLL_INTERVAL_SECONDS = 2.0
ASCAN_MAX_WAIT_SECONDS = 180.0

# ZAP's own alert risk scale doesn't map onto this framework's Severity
# enum one-to-one; this is an approximate correspondence for reporting
# purposes only, not a claim the two scales are equivalent. Ordered
# highest to lowest risk, so the first match when scanning alerts is the
# most severe one present.
RISK_ORDER = ["High", "Medium", "Low", "Informational"]
RISK_TO_SEVERITY = {
    "High": Severity.CRITICAL,
    "Medium": Severity.HIGH,
    "Low": Severity.MEDIUM,
    "Informational": Severity.LOW,
}

# org.parosproxy.paros.core.scanner.ScannerParam's TARGET_* bitmask
# constants, confirmed via `javap -p -constants` against the actual class
# file inside the running ghcr.io/zaproxy/zaproxy:stable (2.17.0) image --
# not documented anywhere in the zapv2 Python client or its API views.
# TARGET_INJECTABLE_DEFAULT (35 = QUERYSTRING|POSTDATA|PLAINBODY) is ZAP's
# own out-of-the-box default and notably excludes TARGET_URLPATH (16).
TARGET_QUERYSTRING = 1
TARGET_POSTDATA = 2
TARGET_COOKIE = 4
TARGET_HTTPHEADERS = 8
TARGET_URLPATH = 16
TARGET_PLAINBODY = 32
TARGET_INJECTABLE_DEFAULT = 35

# VAmPI's sqli_user_lookup target (GET /users/v1/{username}) is injectable
# only via the URL path segment itself -- with ZAP's default
# target_params_injectable, its active scan never attempts injection there
# at all, which would make a "clean" (no alert) result mean "ZAP never
# tried" rather than "ZAP tried and found nothing". _connect() enables
# TARGET_URLPATH in addition to ZAP's own defaults; any test_name in this
# set gets an explicit evidence caveat if that setting didn't confirm.
PATH_SEGMENT_DEPENDENT_TEST_NAMES = {"sqli_user_lookup"}

# Substrings of ZAP's own active-scan alert names (the `alert` field of
# zap.core.alerts()) that indicate a finding relevant to each test case --
# confirmed via zap.ascan.scanners() against the running daemon, not
# guessed. A value of None means this vulnerability class has no
# corresponding ZAP alert type at all: passed is always True regardless of
# what unrelated alerts fired, since ZAP fundamentally cannot test this,
# not because it tried and found nothing.
ALERT_NAME_HINTS: dict[str, Optional[tuple[str, ...]]] = {
    # VAmPI: GET /users/v1/{username} builds raw SQL via f-string
    # interpolation of the username path segment. ZAP's "SQL Injection"
    # rule (40018) and its per-DBMS time-based variants (40019-40022,
    # 40027) all share this substring in their alert name.
    "sqli_user_lookup": ("sql injection",),
    # crAPI: POST /workshop/api/shop/apply_coupon's coupon_code JSON field
    # is a genuine SQL injection point (see src/vulnerabilities/injection.py).
    # Unlike sqli_user_lookup's path segment, this is a POST body field --
    # covered by ZAP's default target_params_injectable (POSTDATA|PLAINBODY).
    "sqli_apply_coupon": ("sql injection",),
    # crAPI: POST .../coupon/validate-coupon is a NoSQL (MongoDB operator)
    # injection. zap.ascan.scanners() confirms this ZAP build has no
    # NoSQL/MongoDB-specific active scan rule at all.
    "nosqli_coupon_validate": None,
    # JWT forgery: ZAP has no active-scan rule that forges or verifies
    # JWT signatures.
    "jwt_weak_signing_bypass": None,
    "jwt_signature_verification_bypass": None,
    # Excessive Data Exposure (plaintext password / other users' data
    # inside an otherwise-200 JSON response body): ZAP has no generic
    # sensitive-data-in-response-body active scan rule.
    "vampi_debug_endpoint_exposure": None,
    "excessive_user_data_exposure": None,
    # BOLA/IDOR (one valid token reading another user's object): ZAP has
    # no capability to compare two tokens' authorized object sets against
    # each other.
    "bola_basket_access": None,
}

# Placeholder JSON bodies for benchmark_mapping.yaml entries whose target_spec
# declares method: POST (currently crAPI's two coupon endpoints, rest_04).
# These only need to be syntactically valid and harmless -- once the message
# shape is on record in ZAP via send_request(), ZAP's own active scan
# supplies its own payload values for the coupon_code field.
POST_BODY_BY_TEST_NAME: dict[str, dict[str, Any]] = {
    "nosqli_coupon_validate": {"coupon_code": "TEST10"},
    "sqli_apply_coupon": {"coupon_code": "TEST10", "amount": 1},
}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _load_zap_connection(app: str) -> dict[str, Any]:
    """Reads the `zap:` block from config/<app>.yaml (host, port, api_key)."""
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
    Connects to the ZAP daemon and enables URL-path-segment injection on
    top of ZAP's own defaults (TARGET_INJECTABLE_DEFAULT excludes
    TARGET_URLPATH -- see the module-level constants), since
    sqli_user_lookup's injection point is a path segment. Returns
    (client, path_injection_confirmed) -- the second value is read back
    from ZAP itself after setting it, not assumed to have taken effect.
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
    VAmPI's `/books/v1/{book_title}` (row 5, jwt_weak_signing_bypass) needs
    a real book title for ZAP's active scan to probe a genuine resource
    rather than a 404. This listing endpoint requires no auth, matching
    src/vulnerabilities/authentication.py's own discovery step.

    This request runs directly from this script on the host, not proxied
    through ZAP's daemon, so it must hit VAmPI's host-published base_url --
    the internal Docker Compose service hostname (INTERNAL_TARGET_BASE_URL)
    is only resolvable from inside the target's own Docker network, where
    ZAP's daemon lives, not from a plain requests.get() made from the host.
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
    """
    Resolves every `{...}` path template in `endpoint` to a concrete value.
    ZAP's own API rejects a literal, unresolved `{...}` segment as an
    illegal parameter rather than treating it as an ordinary path
    character -- access_url/spider.scan/ascan.scan all return the string
    'illegal_parameter' instead of a real id in that case, which then
    breaks status polling. Returns None if a placeholder could not be
    resolved (caller should log a setup-failure result and skip the scan).
    """
    if "{book_title}" in endpoint:
        book_title = _resolve_vampi_book_title(host_base_url)
        if book_title is None:
            return None
        endpoint = endpoint.format(book_title=book_title)
    if "{id}" in endpoint:
        # Juice Shop's /rest/basket/{id}: this route requires an
        # authenticated session ZAP does not have (requires_auth in
        # config/benchmark_mapping.yaml), so the concrete id scanned
        # doesn't change the outcome -- any small integer keeps the URL
        # well-formed for ZAP's API to accept the scan request at all.
        endpoint = endpoint.format(id=1)
    return endpoint


def _poll_until_complete(
    status_fn: Any,
    scan_id: Any,
    poll_interval: float,
    max_wait: float,
    stage_name: str,
) -> tuple[str, Optional[str]]:
    """
    Polls `status_fn(scan_id)` until it reports 100, times out, or reports
    a non-numeric status. Returns (outcome, caveat):

    - ("ok", None): reached 100% cleanly.
    - ("timeout", <caveat>): didn't reach 100% in time, but whatever
      alerts exist so far are still real, partial data -- not a rejection.
    - ("rejected", <caveat>): `scan_id` isn't a real scan at all (e.g.
      status() returns 'does_not_exist' following a rejected scan request
      such as 'illegal_parameter' for a malformed target URL) -- ZAP never
      actually executed this stage, so no alerts were ever collected.
    """
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
    """
    Builds a raw HTTP request string in the request-line + headers + CRLF +
    body shape ZAP's core.send_request() API expects (an absolute-URI
    request line, per ZAP's own documented usage of this action, removes
    any ambiguity about which host ZAP should connect to when relaying the
    message through its own proxy plumbing).
    """
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
    """
    Runs spider then active scan against `url`, returning
    (alerts, caveats, rejected). `rejected=True` means ZAP refused the scan
    request outright (e.g. a malformed URL) -- this run's own value is in
    recording what ZAP could/couldn't confirm, not in guaranteeing a clean
    scan, so a timeout still returns whatever partial alerts exist while a
    rejection returns none at all and flags the result as inconclusive to
    the caller.

    For method="POST", the seed request is submitted via ZAP's
    core.send_request() (a raw request ZAP records into its history with
    the real method/content-type/body) instead of the GET-only
    core.access_url() -- otherwise ZAP's active scan never sees a message
    shaped like the real POST request and has no JSON field to mutate.
    """
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
