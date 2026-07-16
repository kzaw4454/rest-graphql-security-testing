"""
Dissertation figure generation for the Data Analysis section.

Reads the per-target summary CSVs comparative_stats.py already writes to
results/analysis/ and renders them as static charts. No statistic is
computed here -- coverage rates and severity counts are taken directly
from the CSV values that comparative_stats.py already derived.
"""

from __future__ import annotations

import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
SUMMARY_CSV_DIR = REPO_ROOT / "results" / "analysis"
FIGURES_DIR = REPO_ROOT / "reports" / "figures"

# Target order and architecture match Testing Targets in CLAUDE.md/ProposalReport
# §3.7. Architecture is fixed per-target metadata, not a derived statistic, so
# it is not expected to live in comparative_stats.py's summary CSV output.
TARGETS = (
    ("vampi", "VAmPI", "REST"),
    ("crapi", "crAPI", "REST"),
    ("juiceshop", "Juice Shop", "REST"),
    ("dvga", "DVGA", "GraphQL"),
)

# First two slots of the repo's fixed categorical order, used in that order
# for the two coverage series so the mapping stays stable across figures.
COLOR_ALL_DOCUMENTED = "#2a78d6"  # blue
COLOR_IN_SCOPE_ONLY = "#008300"  # green

# Severity is an ordinal scale rather than an identity category, so it draws
# from the status palette (worst to least severe) instead of the categorical
# colors used for coverage.
SEVERITY_COLORS = {
    "critical": "#d03b3b",
    "high": "#ec835a",
    "medium": "#fab219",
    "low": "#0ca30c",
}
SEVERITY_ORDER = ("critical", "high", "medium", "low")

TEXT_PRIMARY = "#0b0b0b"
TEXT_SECONDARY = "#52514e"
GRIDLINE = "#e1e0d9"


def _read_summary(target: str) -> dict[str, str]:
    """Load one target's metric/value rows from its comparative_stats.py CSV."""
    path = SUMMARY_CSV_DIR / f"{target}_summary.csv"
    if not path.exists():
        raise FileNotFoundError(
            f"No summary CSV for target '{target}' at {path} -- run "
            f"comparative_stats.py --target {target} first."
        )
    with path.open(newline="") as f:
        reader = csv.reader(f)
        next(reader)  # header row: metric,value
        return {row[0]: row[1] for row in reader}


def _x_tick_labels() -> list[str]:
    return [f"{name}\n({arch})" for _, name, arch in TARGETS]


def _style_axes(ax: plt.Axes) -> None:
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_visible(False)
    ax.yaxis.grid(True, color=GRIDLINE, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    ax.tick_params(axis="both", length=0, colors=TEXT_SECONDARY)
    ax.xaxis.label.set_color(TEXT_PRIMARY)
    ax.yaxis.label.set_color(TEXT_PRIMARY)
    ax.title.set_color(TEXT_PRIMARY)


def build_coverage_figure(output_dir: Path = FIGURES_DIR) -> Path:
    """
    Grouped bar chart of coverage_rate_all_documented vs
    coverage_rate_in_scope_only per target, as percentages.

    This is the "coverage reported two ways together" figure required by
    CLAUDE.md's Analysis & Metrics section: showing only one rate would
    understate either the full documented attack surface (§3.7) or what the
    framework can realistically cover given existing architectural
    exclusions (e.g. crAPI's out-of-scope LLM vulnerabilities).
    """
    all_documented = []
    in_scope_only = []
    for target, _, _ in TARGETS:
        summary = _read_summary(target)
        all_documented.append(float(summary["coverage_rate_all_documented"]) * 100)
        in_scope_only.append(float(summary["coverage_rate_in_scope_only"]) * 100)

    x = np.arange(len(TARGETS))
    width = 0.35

    fig, ax = plt.subplots(figsize=(8, 5), facecolor="white")
    ax.set_facecolor("white")

    bars_all = ax.bar(
        x - width / 2,
        all_documented,
        width,
        label="All documented",
        color=COLOR_ALL_DOCUMENTED,
        edgecolor="white",
        linewidth=1.5,
        zorder=3,
    )
    bars_scope = ax.bar(
        x + width / 2,
        in_scope_only,
        width,
        label="In-scope only",
        color=COLOR_IN_SCOPE_ONLY,
        edgecolor="white",
        linewidth=1.5,
        zorder=3,
    )

    ax.bar_label(
        bars_all,
        labels=[f"{v:.1f}%" for v in all_documented],
        padding=3,
        color=TEXT_PRIMARY,
        fontsize=9,
    )
    ax.bar_label(
        bars_scope,
        labels=[f"{v:.1f}%" for v in in_scope_only],
        padding=3,
        color=TEXT_PRIMARY,
        fontsize=9,
    )

    ax.set_ylabel("Coverage rate (%)")
    ax.set_ylim(0, 110)
    ax.set_xticks(x)
    ax.set_xticklabels(_x_tick_labels())
    ax.set_title("Vulnerability coverage by target")
    ax.legend(frameon=False, loc="upper right")
    _style_axes(ax)

    fig.tight_layout()
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "coverage_per_target.png"
    fig.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    return output_path


def build_severity_figure(output_dir: Path = FIGURES_DIR) -> Path:
    """
    Stacked bar chart of confirmed-finding severity counts per target.

    Severity is treated as an ordinal scale (critical down to low) rather
    than a set of unrelated categories, matching how comparative_stats.py's
    severity_distribution() already groups confirmed DETECTION/ADJACENT
    findings for the report's descriptive statistics.
    """
    counts: dict[str, list[int]] = {severity: [] for severity in SEVERITY_ORDER}
    for target, _, _ in TARGETS:
        summary = _read_summary(target)
        for severity in SEVERITY_ORDER:
            counts[severity].append(int(summary[f"severity_{severity}"]))

    x = np.arange(len(TARGETS))
    width = 0.5

    fig, ax = plt.subplots(figsize=(8, 5), facecolor="white")
    ax.set_facecolor("white")

    bottoms = np.zeros(len(TARGETS))
    for severity in SEVERITY_ORDER:
        values = np.array(counts[severity], dtype=float)
        bars = ax.bar(
            x,
            values,
            width,
            bottom=bottoms,
            label=severity.capitalize(),
            color=SEVERITY_COLORS[severity],
            edgecolor="white",
            linewidth=1.5,
            zorder=3,
        )
        labels = [str(int(v)) if v > 0 else "" for v in values]
        ax.bar_label(
            bars,
            labels=labels,
            label_type="center",
            color="white",
            fontsize=9,
            fontweight="bold",
        )
        bottoms += values

    ax.set_ylabel("Confirmed findings (count)")
    ax.set_xticks(x)
    ax.set_xticklabels(_x_tick_labels())
    ax.set_title("Severity distribution of confirmed findings by target")
    ax.legend(frameon=False, loc="upper right")
    _style_axes(ax)

    fig.tight_layout()
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "severity_distribution_per_target.png"
    fig.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    return output_path


def main() -> None:
    coverage_path = build_coverage_figure()
    print(f"Written to {coverage_path.relative_to(REPO_ROOT)}")
    severity_path = build_severity_figure()
    print(f"Written to {severity_path.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
