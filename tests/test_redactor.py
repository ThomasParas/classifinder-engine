"""Tests for the redact() function."""

from classifinder_engine.redactor import redact
from classifinder_engine.scanner import scan

# ── No findings ──────────────────────────────────────────────────────────


def test_no_findings_returns_original():
    text = "Hello, no secrets here."
    redacted, mapping = redact(text, [])
    assert redacted == text
    assert mapping == []


# ── Label style ──────────────────────────────────────────────────────────


def test_label_style_replaces_with_type():
    text = "key=AKIAIOSFODNN7EXAMPLE"
    findings = scan(text, min_confidence=0.0)
    redacted, _ = redact(text, findings, style="label")
    assert "[AWS_ACCESS_KEY_REDACTED]" in redacted
    assert "AKIAIOSFODNN7" not in redacted


# ── Mask style ───────────────────────────────────────────────────────────


def test_mask_style_preserves_prefix():
    text = "key=AKIAIOSFODNN7EXAMPLE"
    findings = scan(text, min_confidence=0.0)
    redacted, _ = redact(text, findings, style="mask")
    assert "AKIA" in redacted
    assert "****" in redacted


# ── Hash style ───────────────────────────────────────────────────────────


def test_hash_style_produces_sha256_label():
    text = "key=AKIAIOSFODNN7EXAMPLE"
    findings = scan(text, min_confidence=0.0)
    redacted, _ = redact(text, findings, style="hash")
    assert "[REDACTED:sha256:" in redacted


# ── Multiple findings ────────────────────────────────────────────────────


def test_multiple_findings_all_redacted():
    text = (
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "GITHUB_TOKEN=ghp_ABCDEFghijklMNOP1234567890abcdefghij"
    )
    findings = scan(text, min_confidence=0.0)
    assert len(findings) >= 2
    redacted, mapping = redact(text, findings, style="label")
    assert "AKIAIOSFODNN7" not in redacted
    assert "ghp_ABCDEF" not in redacted
    assert len(mapping) == len(findings)


# ── Surrounding text preserved ───────────────────────────────────────────


def test_surrounding_text_preserved():
    text = "before AKIAIOSFODNN7EXAMPLE after"
    findings = scan(text, min_confidence=0.0)
    redacted, _ = redact(text, findings, style="label")
    assert redacted.startswith("before ")
    assert redacted.endswith(" after")


# ── Redaction map structure ──────────────────────────────────────────────


def test_redaction_map_has_expected_keys():
    text = "key=AKIAIOSFODNN7EXAMPLE"
    findings = scan(text, min_confidence=0.0)
    _, mapping = redact(text, findings, style="label")
    assert len(mapping) >= 1
    entry = mapping[0]
    assert "finding_id" in entry
    assert "redacted_as" in entry
