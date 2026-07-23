"""
Comparative metrics for REST vs GraphQL vulnerability scan results.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import pandas as pd
import yaml

from src.vulnerabilities.base import ResultSource

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
RESULTS_LOG_ROOT = REPO_ROOT / "results" / "logs"
ANALYSIS_OUTPUT_ROOT = REPO_ROOT / "results" / "analysis"
GROUND_TRUTH_PATH = REPO_ROOT / "config" / "ground_truth.yaml"
BENCHMARK_MAPPING_PATH = REPO_ROOT / "config" / "benchmark_mapping.yaml"

# Row-level metrics only ever count assertions that test the module's target
# vulnerability. A CONTROL row failing means a baseline assumption broke, not
# that a vulnerability was found, so it is never counted here.
FINDING_ROLES = ("detection", "adjacent")


@dataclass
class LoggedResult:
    """One VulnerabilityResult row as persisted by RunLogger's JSONL output."""

    test_name: str
    owasp_category: str
    architecture: str
    target: str
    passed: bool
    severity: str
    evidence: str
    assertion_role: str
    source: str
    extra: dict[str, Any]
    run_id: str
    timestamp: str


@dataclass
class RowLevelMetrics:
    """
    Detection rate / precision / recall / F1 from DETECTION and ADJACENT rows.
    """

    target: str
    true_positives: int
    false_negatives: int
    total_finding_assertions: int
    detection_rate: float
    precision: float
    recall: float
    f1: float


@dataclass
class VulnerabilityCoverage:
    """Tested-vs-documented coverage for one target, from ground_truth.yaml."""

    target: str
    documented_count: int
    tested_count: int
    detected_count: int
    coverage_rate: float
    in_scope_documented_count: int
    in_scope_coverage_rate: float
    untested: list[str] = field(default_factory=list)
    untested_out_of_scope: list[str] = field(default_factory=list)
    tested_not_detected: list[str] = field(default_factory=list)


def _latest_rows_by_test_name(category_dir: Path) -> list[dict[str, Any]]:
    """
    Read every .jsonl file in an owasp_category folder, then for each
    distinct test_name keep only the rows from that test_name's own latest
    run_id. A folder can hold output from several test_names logged at
    different times (e.g. DVGA's api8_2023_security_misconfiguration holds
    rows from graphql_auth_bypass.py, graphql_injection.py, and
    graphql_info_disclosure.py, run separately), so picking a single newest
    file for the whole folder would silently drop older test_names' rows.
    """
    records_by_test_name: dict[str, list[dict[str, Any]]] = {}
    latest_run_id_by_test_name: dict[str, str] = {}

    for jsonl_file in sorted(category_dir.glob("*.jsonl")):
        with jsonl_file.open("r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                test_name = record["test_name"]
                run_id = record["run_id"]
                records_by_test_name.setdefault(test_name, []).append(record)
                if run_id > latest_run_id_by_test_name.get(test_name, ""):
                    latest_run_id_by_test_name[test_name] = run_id

    latest_rows: list[dict[str, Any]] = []
    for test_name, records in records_by_test_name.items():
        latest_run_id = latest_run_id_by_test_name[test_name]
        latest_rows.extend(r for r in records if r["run_id"] == latest_run_id)
    return latest_rows


def _target_dir(target: str, architecture: Optional[str]) -> Path:
    if architecture is not None:
        return RESULTS_LOG_ROOT / architecture / target
    for architecture_dir in sorted(RESULTS_LOG_ROOT.iterdir()):
        if not architecture_dir.is_dir():
            continue
        candidate = architecture_dir / target
        if candidate.is_dir():
            return candidate
    raise FileNotFoundError(
        f"No results/logs/<architecture>/{target}/ directory found under {RESULTS_LOG_ROOT}"
    )


def load_latest_results(
    target: str, architecture: Optional[str] = None
) -> list[LoggedResult]:
    """
    Load each test_name's latest-run rows for every owasp_category folder
    under results/logs/<architecture>/<target>/.
    """
    target_dir = _target_dir(target, architecture)

    results: list[LoggedResult] = []
    for category_dir in sorted(target_dir.iterdir()):
        if not category_dir.is_dir():
            continue  # skip *.manifest.json files sitting alongside category folders
        for record in _latest_rows_by_test_name(category_dir):
            results.append(
                LoggedResult(
                    test_name=record["test_name"],
                    owasp_category=record["owasp_category"],
                    architecture=record["architecture"],
                    target=record["target"],
                    passed=record["passed"],
                    severity=record["severity"],
                    evidence=record["evidence"],
                    assertion_role=record["assertion_role"],
                    # Records logged before ResultSource existed predate the
                    # field entirely; they are all this framework's own
                    # modules, so FRAMEWORK is the correct default rather
                    # than a backfill requirement.
                    source=record.get("source", ResultSource.FRAMEWORK.value),
                    extra=record.get("extra", {}),
                    run_id=record["run_id"],
                    timestamp=record["timestamp"],
                )
            )
    return results


def load_ground_truth(
    target: str, path: Path = GROUND_TRUTH_PATH
) -> list[dict[str, Any]]:
    """
    Documented vulnerabilities for a target. `out_of_scope` and
    `instance_count` default to False/1 for entries predating those fields,
    rather than requiring a backfill.
    """
    with path.open("r") as f:
        data = yaml.safe_load(f) or {}
    entries = data.get(target, [])
    for entry in entries:
        entry.setdefault("out_of_scope", False)
        entry.setdefault("instance_count", 1)
    return entries


def load_benchmark_mapping(
    path: Path = BENCHMARK_MAPPING_PATH,
) -> list[dict[str, Any]]:
    """
    Test-case pairings between this framework's own modules and the
    external benchmarking tools (ZAP, GraphQL Cop), one entry per row of
    the dissertation's test case plan that has a benchmark counterpart.
    """
    with path.open("r") as f:
        entries = yaml.safe_load(f) or []
    return entries


_TOOL_SOURCE = {
    "zap": ResultSource.ZAP.value,
    "graphql_cop": ResultSource.GRAPHQL_COP.value,
}


def benchmark_comparison(target: str) -> pd.DataFrame:
    """
    Joins this framework's own detection results against the corresponding
    benchmark tool's results for every config/benchmark_mapping.yaml entry
    scoped to `target`.

    Framework and tool rows are joined on `test_name`: a mapping entry's
    `framework_test_name` (a single test_name, or a list when the plan's
    test case spans more than one framework module) names the exact
    test_name value both this framework's module and the benchmark
    runner's logged rows share for that test case, distinguished only by
    `source`. A row with no logged results yet for one side reports that
    side's `*_detected` as None rather than False, since "not run" and
    "run and found nothing" are different states for the dissertation's
    data to distinguish.

    Tool rows tagged `extra={"inconclusive": True}` are excluded from
    `tool_rows` entirely, so a benchmark runner's own setup failure (e.g.
    zap_runner.py couldn't build a valid scan URL, or a tool subprocess
    never actually ran) falls back to the same `tool_detected=None`
    behaviour as if no row existed at all -- not `False`, which would
    misrepresent "the tool never ran" as "the tool ran and found nothing".
    """
    columns = [
        "id",
        "test_case",
        "app",
        "tool",
        "classification",
        "framework_detected",
        "tool_detected",
        "framework_evidence",
        "tool_evidence",
    ]
    mapping = [
        entry for entry in load_benchmark_mapping() if entry["app"] == target
    ]
    if not mapping:
        return pd.DataFrame(columns=columns)

    results = load_latest_results(target)

    rows: list[dict[str, Any]] = []
    for entry in mapping:
        framework_test_names = entry["framework_test_name"]
        if isinstance(framework_test_names, str):
            framework_test_names = [framework_test_names]
        tool_source = _TOOL_SOURCE[entry["tool"]]

        framework_rows = [
            r
            for r in results
            if r.test_name in framework_test_names
            and r.source == ResultSource.FRAMEWORK.value
            and r.assertion_role in FINDING_ROLES
        ]
        tool_rows = [
            r
            for r in results
            if r.test_name in framework_test_names
            and r.source == tool_source
            and not r.extra.get("inconclusive")
        ]

        rows.append(
            {
                "id": entry["id"],
                "test_case": entry["test_case"],
                "app": entry["app"],
                "tool": entry["tool"],
                "classification": entry["classification"],
                "framework_detected": (
                    any(not r.passed for r in framework_rows)
                    if framework_rows
                    else None
                ),
                "tool_detected": (
                    any(not r.passed for r in tool_rows) if tool_rows else None
                ),
                "framework_evidence": "; ".join(r.evidence for r in framework_rows),
                "tool_evidence": "; ".join(r.evidence for r in tool_rows),
            }
        )

    return pd.DataFrame(rows, columns=columns)


def compute_row_level_metrics(
    target: str, results: list[LoggedResult]
) -> RowLevelMetrics:
    """
    TP/FN from DETECTION/ADJACENT rows only: passed=False -> TP (vulnerability
    confirmed), passed=True -> FN. Benchmark tool rows (source=zap/graphql_cop)
    are excluded — this framework's own detection rate must not be inflated
    by a separate tool's results logged alongside it.
    """
    finding_rows = [
        r
        for r in results
        if r.assertion_role in FINDING_ROLES
        and r.source == ResultSource.FRAMEWORK.value
    ]
    true_positives = sum(1 for r in finding_rows if not r.passed)
    false_negatives = sum(1 for r in finding_rows if r.passed)
    total = len(finding_rows)

    recall = (
        true_positives / (true_positives + false_negatives)
        if (true_positives + false_negatives)
        else 0.0
    )
    precision = 1.0 if true_positives > 0 else 0.0
    f1 = (
        (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    )

    return RowLevelMetrics(
        target=target,
        true_positives=true_positives,
        false_negatives=false_negatives,
        total_finding_assertions=total,
        detection_rate=recall,
        precision=precision,
        recall=recall,
        f1=f1,
    )


def compute_vulnerability_coverage(
    target: str, results: list[LoggedResult], ground_truth: list[dict[str, Any]]
) -> VulnerabilityCoverage:
    """
    "detected":  atleast one of its test_names appears among the loaded rows
    with assertion_role and passed=False
    """
    confirmed_test_names = {
        r.test_name
        for r in results
        if r.assertion_role in FINDING_ROLES
        and not r.passed
        and r.source == ResultSource.FRAMEWORK.value
    }

    documented_count = sum(v["instance_count"] for v in ground_truth)
    tested_count = sum(v["instance_count"] for v in ground_truth if v["tested"])
    untested = [
        v["vulnerability"]
        for v in ground_truth
        if not v["tested"] and not v["out_of_scope"]
    ]
    untested_out_of_scope = [
        v["vulnerability"]
        for v in ground_truth
        if not v["tested"] and v["out_of_scope"]
    ]

    in_scope_ground_truth = [v for v in ground_truth if not v["out_of_scope"]]
    in_scope_documented_count = sum(v["instance_count"] for v in in_scope_ground_truth)
    in_scope_tested_count = sum(
        v["instance_count"] for v in in_scope_ground_truth if v["tested"]
    )

    tested_not_detected = []
    detected_count = 0
    for vuln in ground_truth:
        if not vuln["tested"]:
            continue
        if any(name in confirmed_test_names for name in vuln["test_names"]):
            detected_count += 1
        else:
            tested_not_detected.append(vuln["vulnerability"])

    return VulnerabilityCoverage(
        target=target,
        documented_count=documented_count,
        tested_count=tested_count,
        detected_count=detected_count,
        coverage_rate=(tested_count / documented_count) if documented_count else 0.0,
        in_scope_documented_count=in_scope_documented_count,
        in_scope_coverage_rate=(
            (in_scope_tested_count / in_scope_documented_count)
            if in_scope_documented_count
            else 0.0
        ),
        untested=untested,
        untested_out_of_scope=untested_out_of_scope,
        tested_not_detected=tested_not_detected,
    )


def severity_distribution(results: list[LoggedResult]) -> dict[str, int]:
    """
    Counts by severity across the given rows. Supporting descriptive stats
    only -- not part of detection rate / precision / recall / F1.
    """
    counts: dict[str, int] = {}
    for r in results:
        counts[r.severity] = counts.get(r.severity, 0) + 1
    return counts


def _print_summary(
    target: str,
    row_metrics: RowLevelMetrics,
    coverage: VulnerabilityCoverage,
    severity_counts: dict[str, int],
) -> None:
    print(f"=== Comparative stats: {target} ===\n")

    print("-- Row-level (DETECTION/ADJACENT rows only) --")
    print(f"True positives:            {row_metrics.true_positives}")
    print(f"False negatives:           {row_metrics.false_negatives}")
    print(f"Total finding assertions:  {row_metrics.total_finding_assertions}")
    print(f"Detection rate:            {row_metrics.detection_rate:.4f}")
    print(f"Precision:                 {row_metrics.precision:.4f}")
    print(f"Recall:                    {row_metrics.recall:.4f}")
    print(f"F1:                        {row_metrics.f1:.4f}")
    print(
        "Note: precision/F1 are structurally 1.0 whenever any vulnerability is "
        "detected -- no known-negative test cases exist yet to produce a false "
        "positive under the current test design (see false-positive-rate "
        "caveat below)."
    )
    print()

    print("-- Vulnerability-level coverage (config/ground_truth.yaml) --")
    print(f"Documented vulnerabilities:        {coverage.documented_count}")
    print(f"In-scope documented vulnerabilities: {coverage.in_scope_documented_count}")
    print(f"Tested vulnerabilities:            {coverage.tested_count}")
    print(f"Coverage rate (all documented):   {coverage.coverage_rate:.4f}")
    print(f"Coverage rate (in-scope only):     {coverage.in_scope_coverage_rate:.4f}")
    print(f"Detected this run:                 {coverage.detected_count}")
    if coverage.untested:
        print("Untested (in scope, no test module yet):")
        for name in coverage.untested:
            print(f"  - {name}")
    if coverage.untested_out_of_scope:
        print("Excluded by design (out of scope):")
        for name in coverage.untested_out_of_scope:
            print(f"  - {name}")
    if coverage.tested_not_detected:
        print("Tested but not detected in this run:")
        for name in coverage.tested_not_detected:
            print(f"  - {name}")
    print()

    print("-- Severity distribution (confirmed findings) --")
    for severity in ("critical", "high", "medium", "low"):
        if severity in severity_counts:
            print(f"{severity.capitalize():10s} {severity_counts[severity]}")
    print()

    print("-- Deferred (see CLAUDE.md's Analysis & Metrics section) --")
    print("False positive rate: not computed (no known-negative test cases)")
    print("Mann-Whitney U / Chi-square / Cohen's d: stretch goal, not run")


def _write_summary_csv(
    path: Path,
    target: str,
    row_metrics: RowLevelMetrics,
    coverage: VulnerabilityCoverage,
    severity_counts: dict[str, int],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "value"])
        writer.writerow(["target", target])
        writer.writerow(["true_positives", row_metrics.true_positives])
        writer.writerow(["false_negatives", row_metrics.false_negatives])
        writer.writerow(
            ["total_finding_assertions", row_metrics.total_finding_assertions]
        )
        writer.writerow(["detection_rate", f"{row_metrics.detection_rate:.4f}"])
        writer.writerow(["precision", f"{row_metrics.precision:.4f}"])
        writer.writerow(["recall", f"{row_metrics.recall:.4f}"])
        writer.writerow(["f1", f"{row_metrics.f1:.4f}"])
        writer.writerow(["documented_vulnerabilities", coverage.documented_count])
        writer.writerow(
            ["in_scope_documented_vulnerabilities", coverage.in_scope_documented_count]
        )
        writer.writerow(["tested_vulnerabilities", coverage.tested_count])
        writer.writerow(["coverage_rate_all_documented", f"{coverage.coverage_rate:.4f}"])
        writer.writerow(
            ["coverage_rate_in_scope_only", f"{coverage.in_scope_coverage_rate:.4f}"]
        )
        writer.writerow(["detected_this_run", coverage.detected_count])
        writer.writerow(["untested_vulnerabilities", "; ".join(coverage.untested)])
        writer.writerow(
            [
                "untested_out_of_scope_vulnerabilities",
                "; ".join(coverage.untested_out_of_scope),
            ]
        )
        writer.writerow(
            [
                "tested_not_detected_vulnerabilities",
                "; ".join(coverage.tested_not_detected),
            ]
        )
        for severity in ("critical", "high", "medium", "low"):
            writer.writerow([f"severity_{severity}", severity_counts.get(severity, 0)])
        # Explicitly recorded as deferred/caveated rather than left as a silent
        # gap -- see the module docstring and CLAUDE.md's Analysis & Metrics
        # section. precision_f1_caveat travels with the CSV so the trivial-1.0
        # artifact isn't mistaken for a real accuracy measurement if this file
        # is used directly in the report without the stdout text.
        writer.writerow(["false_positive_rate", "not_computed"])
        writer.writerow(
            ["precision_f1_caveat", "trivially_1.0_no_known_negative_cases"]
        )
        writer.writerow(["mann_whitney_u_chi_square_cohens_d", "deferred_stretch_goal"])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        default="vampi",
        help="Target to analyse (e.g. vampi, crapi, juiceshop, dvga)",
    )
    args = parser.parse_args()

    results = load_latest_results(args.target)
    ground_truth = load_ground_truth(args.target)
    if not ground_truth:
        raise SystemExit(
            f"No config/ground_truth.yaml entries found for target '{args.target}'"
        )

    row_metrics = compute_row_level_metrics(args.target, results)
    coverage = compute_vulnerability_coverage(args.target, results, ground_truth)
    confirmed_findings = [
        r for r in results if r.assertion_role in FINDING_ROLES and not r.passed
    ]
    severity_counts = severity_distribution(confirmed_findings)

    _print_summary(args.target, row_metrics, coverage, severity_counts)

    output_path = ANALYSIS_OUTPUT_ROOT / f"{args.target}_summary.csv"
    _write_summary_csv(output_path, args.target, row_metrics, coverage, severity_counts)
    print(f"\nWritten to {output_path.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
