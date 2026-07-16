"""Unit tests for dissertation figure generation."""

from src.analysis import visualization


def test_build_coverage_figure_writes_nonempty_png(tmp_path):
    output_path = visualization.build_coverage_figure(output_dir=tmp_path)
    assert output_path.exists()
    assert output_path.stat().st_size > 0


def test_build_severity_figure_writes_nonempty_png(tmp_path):
    output_path = visualization.build_severity_figure(output_dir=tmp_path)
    assert output_path.exists()
    assert output_path.stat().st_size > 0
