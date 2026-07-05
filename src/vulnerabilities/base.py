"""
Common interface for vulnerability test modules.

Per CLAUDE.md: "Each vulnerability module implements a common `test_*`
interface so results are comparable across REST and GraphQL scanners."

This file defines that shared contract only — it contains no test logic
for any specific vulnerability. Concrete modules (e.g. authorization.py,
injection.py) subclass VulnerabilityTest and implement `run()`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class VulnerabilityResult:
    """
    Standardised result of a single vulnerability test run.

    Fields map to what src/analysis/ needs for comparative statistics
    and OWASP mapping (see CLAUDE.md, §3.4/§3.5 of the proposal).
    """

    test_name: str
    owasp_category: str          # e.g. "API1:2023 Broken Object Level Authorization"
    architecture: str            # "rest" or "graphql"
    target: str                  # e.g. "vampi", "dvga"
    passed: bool                 # True = no vulnerability detected, False = vulnerability found
    severity: Severity
    evidence: str                # human-readable description of what was observed
    request_summary: Optional[str] = None   # e.g. method + path, redacted of secrets
    response_summary: Optional[str] = None  # e.g. status code + relevant snippet
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def is_vulnerable(self) -> bool:
        return not self.passed


class VulnerabilityTest(ABC):
    """
    Base class all vulnerability test modules implement.

    Subclasses must set `name` and `owasp_category`, and implement `run()`
    to return a list of VulnerabilityResult (one test can produce multiple
    results, e.g. testing several endpoints for the same category).
    """

    name: str = "unnamed_test"
    owasp_category: str = "unmapped"

    def __init__(self, architecture: str, target: str) -> None:
        self.architecture = architecture
        self.target = target

    @abstractmethod
    def run(self) -> list[VulnerabilityResult]:
        """Execute the test and return one or more results."""
        raise NotImplementedError

    def _result(
        self,
        passed: bool,
        severity: Severity,
        evidence: str,
        request_summary: Optional[str] = None,
        response_summary: Optional[str] = None,
        **extra: Any,
    ) -> VulnerabilityResult:
        """Convenience factory so subclasses don't repeat boilerplate fields."""
        return VulnerabilityResult(
            test_name=self.name,
            owasp_category=self.owasp_category,
            architecture=self.architecture,
            target=self.target,
            passed=passed,
            severity=severity,
            evidence=evidence,
            request_summary=request_summary,
            response_summary=response_summary,
            extra=extra,
        )