#!/usr/bin/env python3
"""
Pre-commit provenance check for classifinder-engine patterns.

Verifies that every re.compile() in staged patterns/*.py files
has a source comment within the 5 preceding lines.

Accepted source comment markers:
  # Source:
  # Format per
  # Pattern attribution:
  # Independently authored
  # Vendor-published
"""

import re
import subprocess
import sys

SOURCE_MARKERS = [
    "# Source:",
    "# Format",          # covers "# Format per", "# Format derived from", etc.
    "# Pattern attribution:",
    "# Independently",   # covers "# Independently authored", "# Independently derived"
    "# Vendor-published",
    "# Vendor format",
    "# Common knowledge",
    "# RFC ",
    "# PCI",
]


def get_staged_pattern_files() -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        capture_output=True, text=True,
    )
    return [
        f for f in result.stdout.splitlines()
        if re.match(r"patterns/[^/]+\.py$", f) and f != "patterns/registry.py"
    ]


def get_staged_content(filepath: str) -> str:
    result = subprocess.run(
        ["git", "show", f":{filepath}"],
        capture_output=True, text=True,
    )
    return result.stdout


def check_provenance(filepath: str, content: str) -> list[tuple[int, str]]:
    """Return list of (line_number, snippet) for re.compile() lines missing source comments."""
    lines = content.splitlines()
    failures = []
    for i, line in enumerate(lines):
        if "re.compile(" in line and "# re.compile(" not in line:
            window = lines[max(0, i - 5) : i]
            has_source = any(
                any(marker in wline for marker in SOURCE_MARKERS)
                for wline in window
            )
            if not has_source:
                failures.append((i + 1, line.strip()))
    return failures


def main() -> None:
    staged = get_staged_pattern_files()
    if not staged:
        sys.exit(0)

    any_failure = False
    for filepath in staged:
        content = get_staged_content(filepath)
        failures = check_provenance(filepath, content)
        if failures:
            any_failure = True
            print(f"\nPROVENANCE CHECK FAILED: {filepath}")
            for lineno, snippet in failures:
                print(f"  Line {lineno}: {snippet[:100]}")
            print("\n  Every re.compile() must have a source comment within 5 lines above it.")
            print("  Accepted formats:")
            for marker in SOURCE_MARKERS:
                print(f"    {marker} ...")

    if any_failure:
        print("\nSee pattern-tuning-guide.md (classifinder-knowledge vault) for the full policy.")
        print("TruffleHog (AGPL) must never be the source — rewrite from vendor docs.")
        sys.exit(1)

    print("Pattern provenance check passed.")
    sys.exit(0)


if __name__ == "__main__":
    main()
