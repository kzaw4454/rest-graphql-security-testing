"""
GraphQL Cop benchmark runner (DVGA).

Drives the dolevf/graphql-cop CLI against DVGA's /graphql endpoint for
every config/benchmark_mapping.yaml entry tagged `tool: graphql_cop`, and
logs the outcome as VulnerabilityResult rows (source=GRAPHQL_COP) via the
same RunLogger every framework module uses. This lets
comparative_stats.py's benchmark_comparison() join GraphQL Cop's results
against this framework's own detection results for the dissertation's
benchmarking section.

graphql-cop has no packaging at all (no setup.py/pyproject.toml) -- it is
vendored as source under benchmarks/graphql-cop/, with its own isolated
venv at benchmarks/graphql-cop/venv/ (its pinned requests==2.25.1
conflicts with this project's own requests requirement). Set up with:

    git clone https://github.com/dolevf/graphql-cop.git benchmarks/graphql-cop
    python3 -m venv benchmarks/graphql-cop/venv
    benchmarks/graphql-cop/venv/bin/pip install -r benchmarks/graphql-cop/requirements.txt

See notes/notes_benchmarks/graphql_cop_runner.md for the exact CLI
invocation and JSON schema, confirmed directly against the tool's actual
source and a live run.
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

# DVGA's own vulnerability tests each need a specific difficulty mode to
# reproduce the finding (see src/vulnerabilities/graphql_info_disclosure.py
# and graphql_dos.py) -- graphql_cop has no per-check difficulty control of
# its own, so this runner sets DVGA's difficulty before each CLI invocation
# and reuses one run's output across every test_name that needs the same
# mode, rather than re-running the tool per test_name.
DIFFICULTY_BY_TEST_NAME = {
    "introspection_exposure": "easy",
    "field_suggestion_info_disclosure": "hard",
    "deep_nesting_dos": "easy",
    "batch_query_dos": "easy",
}

# Exact `title` values graphql-cop's own checks report, confirmed against
# lib/tests/*.py in the vendored checkout and a live run against DVGA (see
# notes/notes_benchmarks/graphql_cop_runner.md) -- matched by exact
# (case-insensitive) equality, not substring containment, since e.g.
# "Introspection" and "Introspection-based Circular Query" both contain
# "introspection" and would otherwise be conflated. A value of None means
# graphql-cop has no corresponding check at all.
CHECK_NAME_HINTS: dict[str, Optional[tuple[str, ...]]] = {
    "introspection_exposure": ("introspection",),
    "field_suggestion_info_disclosure": ("field suggestions",),
    "deep_nesting_dos": ("introspection-based circular query",),
    "batch_query_dos": ("array-based query batching",),
}

# deep_nesting_dos's mapped check tests a genuinely different mechanism
# than this framework's own test (see module docstring reasoning in
# notes/notes_benchmarks/graphql_cop_runner.md) -- this caveat is appended
# to its evidence whenever a match is found, so the dissertation table
# doesn't read the two as equivalent coverage.
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

# Test names whose mapped graphql-cop check (see CHECK_NAME_HINTS) tests a
# genuinely different mechanism than this framework's own test for the same
# row (see MECHANISM_CAVEATS) -- a match from graphql-cop here does not
# confirm it detected the same vulnerability, so these are never counted as
# a detection regardless of what graphql-cop's report says. The evidence
# text still reports graphql-cop's actual result and the mechanism caveat,
# so the mismatch stays visible rather than silently forcing a clean pass.
MECHANISM_MISMATCH_TEST_NAMES = {"deep_nesting_dos"}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _load_graphql_cop_config(config_path: str = "config/dvga.yaml") -> dict[str, Any]:
    """Reads the `graphql_cop:` block from config/dvga.yaml (script_path, python_path)."""
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
    Runs graphql-cop against `endpoint` via its own isolated venv's python
    interpreter and returns its parsed JSON report, or None if the
    invocation itself failed (subprocess error, timeout, non-JSON output).

    `-o json` prints a JSON array directly to stdout (confirmed from
    graphql-cop.py's source: `print(dumps(json_output))`) -- it is not a
    file path despite the option's help text reading just "json"; there is
    no `-o <file>` form.
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
    title = str(check.get("title", "")).strip().lower()
    return title in hints


def _check_is_vulnerable(check: dict[str, Any]) -> bool:
    return bool(check.get("result", False))


def _result_for_entry(
    test_name: str,
    owasp_category: str,
    checks: Optional[list[dict[str, Any]]],
    difficulty: str,
) -> VulnerabilityResult:
    if checks is None:
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
