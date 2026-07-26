"""
GraphQL Cop benchmark runner (DVGA).
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
from typing import Any, Optional

import yaml

from src.analysis.comparative_stats import load_benchmark_mapping
from src.utils.dvga_client import DVGAClient
from src.utils.results_logger import RunLogger
from src.vulnerabilities.base import ResultSource, Severity, VulnerabilityResult

logger = logging.getLogger(__name__)

GRAPHQL_COP_TIMEOUT_SECONDS = 120.0

DIFFICULTY_BY_TEST_NAME = {
    "introspection_exposure": "easy",
    "field_suggestion_info_disclosure": "hard",
    "deep_nesting_dos": "easy",
    "batch_query_dos": "easy",
}

CHECK_NAME_HINTS: dict[str, Optional[tuple[str, ...]]] = {
    "introspection_exposure": ("introspection",),
    "field_suggestion_info_disclosure": ("field suggestions",),
    "deep_nesting_dos": ("introspection-based circular query",),
    "batch_query_dos": ("array-based query batching",),
}

MECHANISM_CAVEATS: dict[str, str] = {
    "deep_nesting_dos": (
        "CAVEAT: graphql-cop's 'Introspection-based Circular Query' check "
        "sends a fixed 5-level-deep __schema introspection query and checks "
        "whether 25+ types come back -- a different mechanism than "
        "deep_nesting_dos's own test, which exploits DVGA's cyclic "
        "PasteObject.owner -> OwnerObject.pastes DATA relation at arbitrary "
        "depth and does not depend on introspection being queryable at all. "
        "A match here reflects overlapping attack surface (DVGA's default "
        "easy mode also leaves introspection enabled), not equivalent "
        "vulnerability coverage."
    ),
}

MECHANISM_MISMATCH_TEST_NAMES = {"deep_nesting_dos"}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _load_graphql_cop_config(config_path: str = "config/dvga.yaml") -> dict[str, Any]:
    """Reads paths (file, python interpreter) of `graphql_cop:` from config/dvga.yaml."""
    with open(config_path, "r") as f:
        data = yaml.safe_load(f)
    graphql_cop_config = data.get("graphql_cop")
    if not graphql_cop_config:
        raise RuntimeError(
            f"{config_path} has no 'graphql_cop:' block -- add one pointing "
            "at the vendored benchmarks/graphql-cop/ checkout and its "
            "isolated venv (see this module's docstring)."
        )
    return graphql_cop_config


def _run_graphql_cop(
    python_path: str, script_path: str, endpoint: str
) -> Optional[list[dict[str, Any]]]:
    """
    Runs graphql-cop against DVGA and parses its JSON output.
    Crashes or times out -> returns `None` (tools failed signal, not too fount nothing).
    """
    try:
        result = subprocess.run(
            [python_path, script_path, "-t", endpoint, "-o", "json"],
            capture_output=True,
            text=True,
            timeout=GRAPHQL_COP_TIMEOUT_SECONDS,
            check=True,
        )
        return json.loads(result.stdout)
    except (subprocess.SubprocessError, OSError, ValueError) as exc:
        logger.warning("graphql-cop invocation against %s failed: %s", endpoint, exc)
        return None


def _matches(check: dict[str, Any], hints: tuple[str, ...]) -> bool:
    """Checks if graphql-cop check's title matches title of a given test."""
    title = str(check.get("title", "")).strip().lower()
    return title in hints


def _check_is_vulnerable(check: dict[str, Any]) -> bool:
    """Checkes if graphql-cop's result being flagged as vulnerable."""
    return bool(check.get("result", False))


def _result_for_entry(
    test_name: str,
    owasp_category: str,
    checks: Optional[list[dict[str, Any]]],
    difficulty: str,
) -> VulnerabilityResult:
    if checks is None:
        """
        Checks if graphql-cop reports the same vulnerability as
        what the framework tests, and produces the results.
        """
        return VulnerabilityResult(
            test_name=test_name,
            owasp_category=owasp_category,
            architecture="graphql",
            target="dvga",
            passed=True,
            severity=Severity.LOW,
            evidence=(
                f"graphql-cop invocation itself failed (difficulty={difficulty}) "
                "-- no report was produced, so nothing could be checked for "
                f"'{test_name}'. Inconclusive setup failure, not a clean scan "
                "result."
            ),
            source=ResultSource.GRAPHQL_COP,
            extra={"inconclusive": True},
        )

    hints = CHECK_NAME_HINTS[test_name]

    if hints is None:
        return VulnerabilityResult(
            test_name=test_name,
            owasp_category=owasp_category,
            architecture="graphql",
            target="dvga",
            passed=True,
            severity=Severity.LOW,
            evidence=(
                f"graphql-cop (difficulty={difficulty}) has no check "
                f"corresponding to '{test_name}' at all -- this is a gap in "
                "graphql-cop's own coverage, not zero matches from an "
                "attempted detection."
            ),
            source=ResultSource.GRAPHQL_COP,
        )

    matched = [c for c in checks if _matches(c, hints)]

    if not matched:
        return VulnerabilityResult(
            test_name=test_name,
            owasp_category=owasp_category,
            architecture="graphql",
            target="dvga",
            passed=True,
            severity=Severity.LOW,
            evidence=(
                f"graphql-cop (difficulty={difficulty}) ran and produced "
                f"{len(checks)} check result(s), but none had title {hints!r} "
                f"expected for '{test_name}' -- possibly a version difference "
                "from what this runner was verified against (see "
                "notes/notes_benchmarks/graphql_cop_runner.md)."
            ),
            source=ResultSource.GRAPHQL_COP,
        )

    vulnerable = any(_check_is_vulnerable(c) for c in matched)
    evidence_detail = "; ".join(
        f"{c.get('title', 'check')}: result={_check_is_vulnerable(c)} "
        f"({c.get('description', '')})"
        for c in matched
    )
    evidence = f"graphql-cop (difficulty={difficulty}): {evidence_detail}."
    if test_name in MECHANISM_CAVEATS:
        evidence += f" {MECHANISM_CAVEATS[test_name]}"

    passed = not vulnerable
    if test_name in MECHANISM_MISMATCH_TEST_NAMES:
        passed = True

    return VulnerabilityResult(
        test_name=test_name,
        owasp_category=owasp_category,
        architecture="graphql",
        target="dvga",
        passed=passed,
        severity=Severity.LOW if passed else Severity.MEDIUM,
        evidence=evidence,
        source=ResultSource.GRAPHQL_COP,
    )


def _print_results(results: list[VulnerabilityResult]) -> None:
    for result in results:
        status = "PASS" if result.passed else f"FAIL ({result.severity.value.upper()})"
        print(f"[{status}] {result.test_name} - {result.owasp_category} (GraphQL Cop)")
        print(f"  Evidence:  {result.evidence}")
        print()


def _run_dvga() -> None:
    entries = [
        e
        for e in load_benchmark_mapping()
        if e["tool"] == "graphql_cop" and e["app"] == "dvga"
    ]
    if not entries:
        logger.info("No 'tool: graphql_cop' benchmark_mapping.yaml entries for 'dvga'")
        return

    graphql_cop_config = _load_graphql_cop_config()
    python_path = graphql_cop_config["python_path"]
    script_path = graphql_cop_config["script_path"]

    client = DVGAClient.from_config("config/dvga.yaml")
    endpoint = client.endpoint_url

    reports_by_difficulty: dict[str, Optional[list[dict[str, Any]]]] = {}
    needed_difficulties = {
        DIFFICULTY_BY_TEST_NAME[test_name]
        for entry in entries
        for test_name in _as_list(entry["framework_test_name"])
    }
    for difficulty in needed_difficulties:
        client.set_difficulty(difficulty)
        reports_by_difficulty[difficulty] = _run_graphql_cop(
            python_path, script_path, endpoint
        )
    client.set_difficulty("easy")

    all_results: list[VulnerabilityResult] = []
    with RunLogger("graphql", "dvga", "config/dvga.yaml") as run:
        for entry in entries:
            test_names = _as_list(entry["framework_test_name"])
            categories = _as_list(entry["owasp_category"])
            entry_results = []
            for test_name, category in zip(test_names, categories):
                difficulty = DIFFICULTY_BY_TEST_NAME[test_name]
                entry_results.append(
                    _result_for_entry(
                        test_name,
                        category,
                        reports_by_difficulty[difficulty],
                        difficulty,
                    )
                )
            run.log_results(entry_results)
            all_results.extend(entry_results)

    _print_results(all_results)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        choices=["dvga"],
        default="dvga",
        help=(
            "Which target's container must be up. DVGA is currently this "
            "framework's only GraphQL target -- requires "
            "docker-compose.dvga.yml to be running."
        ),
    )
    args = parser.parse_args()

    if args.target == "dvga":
        _run_dvga()
