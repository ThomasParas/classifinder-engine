"""ClassiFinder Engine — standalone secret detection.

Pure-function scanner and redactor. No I/O, no network, no state.

Quick start:
    from classifinder_engine import scan, redact

    findings = scan("AKIAIOSFODNN7EXAMPLE")
    redacted, _ = redact("token=AKIAIOSFODNN7EXAMPLE", findings, style="label")
"""

from classifinder_engine.patterns.registry import PATTERN_REGISTRY
from classifinder_engine.redactor import redact
from classifinder_engine.scanner import Finding, scan

__all__ = ["Finding", "PATTERN_REGISTRY", "redact", "scan"]
