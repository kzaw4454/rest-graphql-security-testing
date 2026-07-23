"""
Common interface for vulnerability test modules.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    LOW = "low" # confirms the baseline (mostly 'control' assertion)
    MEDIUM = "medium" # vulnerability exists but impact is limited
    HIGH = "high" # exploited but scoped to one object/record
    CRITICAL = "critical" # unbounded exploit or privileged impact (potential to whole system takeover)


class AssertionRole(str, Enum):
    DETECTION = "detection" # tests the documented, in-scope vulnerability
    CONTROL = "control"     # baseline expectation; failure here is not the target vuln (not counted for statistics)
    ADJACENT = "adjacent"   # control that failed and IS itself a real, separate, in-scope finding


class ResultSource(str, Enum):
    """Which tool produced a result — orthogonal to assertion_role."""

    FRAMEWORK = "framework"       # this project's own vulnerability test modules
    ZAP = "zap"                   # OWASP ZAP benchmark scan
    GRAPHQL_COP = "graphql_cop"   # GraphQL Cop benchmark scan


@dataclass
class VulnerabilityResult:
    """
    Standardised result of a single vulnerability test run.
    The result is logged under results/logs/.
    """

    test_name: str
    owasp_category: str  # e.g. "API1:2023 Broken Object Level Authorization"
    architecture: str  # "rest" or "graphql"
    target: str  # e.g. "vampi", "dvga"
    passed: bool  # True = no vulnerability detected, False = vulnerability found
    severity: Severity
    evidence: str  # human-readable description of what was observed
    request_summary: Optional[str] = None  # e.g. method + path, redacted of secrets
    response_summary: Optional[str] = None  # e.g. status code + relevant snippet
    assertion_role: AssertionRole = AssertionRole.DETECTION
    source: ResultSource = ResultSource.FRAMEWORK
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def is_vulnerable(self) -> bool:
        return not self.passed


class VulnerabilityTest(ABC):
    """
    Base class for all vulnerability test modules
    e.g. authorization.py, injection.py, graphql_dos.py
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
        assertion_role: AssertionRole = AssertionRole.DETECTION,
        **extra: Any,
    ) -> VulnerabilityResult:
        """Factory for subclasses not to repeat boilerplate fields."""
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
            assertion_role=assertion_role,
            extra=extra,
        )
