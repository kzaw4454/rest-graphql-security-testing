"""
Structured JSONL logging for vulnerability test run results.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from types import TracebackType
from typing import Any, Optional

from src.vulnerabilities.base import VulnerabilityResult

REPO_ROOT = Path(__file__).resolve().parents[2]
RESULTS_LOG_ROOT = REPO_ROOT / "results" / "logs"


def _slugify(value: str) -> str:
    """Lowercase, filesystem-safe slug for an owasp_category string."""
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _git_commit_sha() -> Optional[str]:
    """Current commit SHA, best-effort. None outside a git checkout."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        return result.stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return None


def _new_run_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{timestamp}_{uuid.uuid4().hex[:6]}"


class RunLogger:
    def __init__(
        self,
        architecture: str,
        target: str,
        config_path: str,
        log_root: Path = RESULTS_LOG_ROOT,
    ) -> None:
        self.architecture = architecture
        self.target = target
        self.config_path = config_path
        self.run_id = _new_run_id()
        self._target_dir = log_root / architecture / target
        self._manifest_path = self._target_dir / f"{self.run_id}.manifest.json"
        self._passed = 0
        self._failed = 0
        self._manifest: dict[str, Any] = {}

    def __enter__(self) -> "RunLogger":
        self._target_dir.mkdir(parents=True, exist_ok=True)
        self._manifest = {
            "run_id": self.run_id,
            "architecture": self.architecture,
            "target": self.target,
            "start_time": datetime.now(timezone.utc).isoformat(),
            "git_commit": _git_commit_sha(),
            "config_path": self.config_path,
            "python_version": sys.version.split()[0],
            "end_time": None,
            "passed": 0,
            "failed": 0,
            "error": None,
        }
        self._write_manifest()
        return self

    def log_results(self, results: list[VulnerabilityResult]) -> None:
        """Append each result to its owasp_category's JSONL file."""
        by_category: dict[str, list[VulnerabilityResult]] = {}
        for result in results:
            by_category.setdefault(result.owasp_category, []).append(result)

        for owasp_category, category_results in by_category.items():
            category_dir = self._target_dir / _slugify(owasp_category)
            category_dir.mkdir(parents=True, exist_ok=True)
            path = category_dir / f"{self.run_id}.jsonl"
            with path.open("a") as f:
                for result in category_results:
                    record = asdict(result)
                    record["severity"] = result.severity.value
                    record["assertion_role"] = result.assertion_role.value
                    record["run_id"] = self.run_id
                    record["record_type"] = "result"
                    f.write(json.dumps(record) + "\n")
                    f.flush()
                    self._passed += 1 if result.passed else 0
                    self._failed += 0 if result.passed else 1

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self._manifest["end_time"] = datetime.now(timezone.utc).isoformat()
        self._manifest["passed"] = self._passed
        self._manifest["failed"] = self._failed
        self._manifest["error"] = f"{exc_type.__name__}: {exc}" if exc_type else None
        self._write_manifest()

    def _write_manifest(self) -> None:
        with self._manifest_path.open("w") as f:
            json.dump(self._manifest, f, indent=2)
            f.write("\n")
            f.flush()
