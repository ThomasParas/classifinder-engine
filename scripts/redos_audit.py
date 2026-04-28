#!/usr/bin/env python3
"""
ReDoS audit for ClassiFinder pattern library.

Two complementary approaches:
1. Static analysis — flag structural patterns known to cause catastrophic backtracking
2. Timing test — measure match time against pathological inputs with a timeout

Usage:
    python scripts/redos_audit.py
    python scripts/redos_audit.py --json > redos_report.json

Exit code 0 = no high-risk patterns found
Exit code 1 = high-risk patterns found (fix before Batch 4)
"""

from __future__ import annotations

import argparse
import json
import re
import signal
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# Make the engine package importable when run from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from classifinder_engine.patterns.registry import PATTERN_REGISTRY
from classifinder_engine.scanner import scan as _scan


# ---------------------------------------------------------------------------
# Static analysis
# ---------------------------------------------------------------------------

# Patterns that indicate potential ReDoS (Python re backtracking NFA)
_STATIC_RULES: list[tuple[str, str, str]] = [
    # (rule_id, description, regex_to_detect_in_pattern)
    ("nested_quant",    "Nested quantifiers (X+)+ or (X*)* — catastrophic",
     r'\([^()]*[+*][^()]*\)[+*]'),
    ("overlap_alt",     "Alternation with same-prefix branches (a|ab)+ — catastrophic",
     r'\([^()|]*\|[^()|]*\)[+*{]'),
    ("star_star",       "Adjacent wildcards .*.* or [\\w]+[\\w]+ — superlinear",
     r'(?:\.\*|\.\+|\[(?:[^\]]+)\][+*])(?:\.\*|\.\+|\[(?:[^\]]+)\][+*])'),
    ("dotstar_open",    "Unbounded .* without anchor in a loop context",
     r'\.[\*\+]\{'),
]

_STATIC_COMPILED = [
    (rule_id, desc, re.compile(pat))
    for rule_id, desc, pat in _STATIC_RULES
]


def static_flags(pattern_str: str) -> list[tuple[str, str]]:
    """Return list of (rule_id, description) for static ReDoS indicators."""
    flags = []
    for rule_id, desc, detector in _STATIC_COMPILED:
        if detector.search(pattern_str):
            flags.append((rule_id, desc))
    return flags


# ---------------------------------------------------------------------------
# Timing test
# ---------------------------------------------------------------------------

class _Timeout(Exception):
    pass


def _timeout_handler(signum: int, frame: object) -> None:
    raise _Timeout()


# Pathological inputs targeting common ReDoS patterns
_EVIL_INPUTS = [
    # Long string of chars that match \w, \s, letter ranges
    "a" * 100 + "!",
    "a" * 50 + "b" * 50 + "!",
    " " * 100 + "!",
    "A" * 100 + "!",
    "0" * 100 + "!",
    # Mixed context-like strings (target context-keyword patterns)
    "AAAA_API_KEY=" + "x" * 80 + "!",
    "secret=" + "a" * 80 + "!",
    # Long strings for connection string patterns
    "postgres://" + "a" * 60 + "!",
    "redis://" + "a" * 60 + "!",
    # URL patterns
    "https://" + "a" * 60 + ".webhook.office.com/" + "a" * 40 + "!",
]


def timing_test(compiled_regex: re.Pattern, timeout_secs: float = 1.0) -> dict:
    """
    Run regex against pathological inputs with a per-input timeout.

    Returns dict with:
        max_ms: worst observed match time in milliseconds
        timed_out: True if any input exceeded timeout_secs
        evil_input: the input that caused the worst result (truncated)
    """
    worst_ms = 0.0
    worst_input = ""
    timed_out = False

    signal.signal(signal.SIGALRM, _timeout_handler)

    for evil in _EVIL_INPUTS:
        signal.alarm(int(timeout_secs) + 1)
        t0 = time.perf_counter()
        try:
            compiled_regex.search(evil)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            signal.alarm(0)
            if elapsed_ms > worst_ms:
                worst_ms = elapsed_ms
                worst_input = evil
        except _Timeout:
            signal.alarm(0)
            timed_out = True
            worst_input = evil
            worst_ms = timeout_secs * 1000
            break

    return {
        "max_ms": round(worst_ms, 2),
        "timed_out": timed_out,
        "evil_input": worst_input[:60] + ("..." if len(worst_input) > 60 else ""),
    }


# ---------------------------------------------------------------------------
# Risk classification
# ---------------------------------------------------------------------------

def classify(static: list, timing: dict) -> str:
    """Return 'HIGH', 'MEDIUM', or 'LOW'."""
    if timing["timed_out"]:
        return "HIGH"
    if any(r in ("nested_quant", "overlap_alt") for r, _ in static):
        return "HIGH"
    if timing["max_ms"] > 200:
        return "MEDIUM"
    if static or timing["max_ms"] > 50:
        return "LOW"
    return "SAFE"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

@dataclass
class PatternResult:
    pattern_id: str
    regex: str
    risk: str
    static_flags: list[tuple[str, str]]
    max_ms: float
    timed_out: bool
    evil_input: str


def run_audit(timeout_secs: float = 1.0) -> list[PatternResult]:
    results = []
    for p in PATTERN_REGISTRY:
        static = static_flags(p.regex.pattern)
        timing = timing_test(p.regex, timeout_secs=timeout_secs)
        risk = classify(static, timing)
        results.append(PatternResult(
            pattern_id=p.id,
            regex=p.regex.pattern,
            risk=risk,
            static_flags=static,
            max_ms=timing["max_ms"],
            timed_out=timing["timed_out"],
            evil_input=timing["evil_input"],
        ))
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="ReDoS audit for ClassiFinder patterns")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--timeout", type=float, default=1.0, help="Per-input timeout in seconds")
    parser.add_argument("--min-risk", choices=["HIGH", "MEDIUM", "LOW", "SAFE"], default="LOW",
                        help="Minimum risk level to report")
    args = parser.parse_args()

    results = run_audit(timeout_secs=args.timeout)

    risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "SAFE": 3}
    min_level = risk_order[args.min_risk]
    filtered = [r for r in results if risk_order[r.risk] <= min_level]
    filtered.sort(key=lambda r: (risk_order[r.risk], -r.max_ms))

    counts = {k: sum(1 for r in results if r.risk == k) for k in risk_order}

    if args.json:
        print(json.dumps({
            "summary": counts,
            "total": len(results),
            "findings": [
                {
                    "id": r.pattern_id,
                    "risk": r.risk,
                    "max_ms": r.max_ms,
                    "timed_out": r.timed_out,
                    "static_flags": [f[0] for f in r.static_flags],
                    "evil_input": r.evil_input,
                    "regex": r.regex[:120],
                }
                for r in filtered
            ],
        }, indent=2))
        sys.exit(1 if counts["HIGH"] > 0 else 0)

    # Human-readable output
    print(f"\nReDoS Audit — ClassiFinder Pattern Library ({len(results)} patterns)\n")
    print(f"  HIGH    {counts['HIGH']:3d}  — catastrophic backtracking risk, fix before Batch 4")
    print(f"  MEDIUM  {counts['MEDIUM']:3d}  — superlinear, investigate")
    print(f"  LOW     {counts['LOW']:3d}  — minor static flags, monitor")
    print(f"  SAFE    {counts['SAFE']:3d}  — no issues detected")
    print()

    if filtered:
        for r in filtered:
            risk_label = f"[{r.risk}]"
            timeout_note = " TIMEOUT" if r.timed_out else f" {r.max_ms:.0f}ms"
            print(f"{risk_label:8s} {r.pattern_id}")
            for flag_id, flag_desc in r.static_flags:
                print(f"          static: {flag_desc}")
            print(f"          timing:{timeout_note}  input: {r.evil_input}")
            print(f"          regex:  {r.regex[:100]}")
            print()
    else:
        print("  No findings at or above the requested risk level.")

    sys.exit(1 if counts["HIGH"] > 0 else 0)


if __name__ == "__main__":
    main()
