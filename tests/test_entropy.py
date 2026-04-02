"""Tests for the Shannon entropy calculator."""

from classifinder_engine.entropy import shannon_entropy


def test_empty_string_returns_zero():
    assert shannon_entropy("") == 0.0


def test_single_char_returns_zero():
    assert shannon_entropy("a") == 0.0


def test_repeated_char_returns_zero():
    assert shannon_entropy("aaaaaaa") == 0.0


def test_two_distinct_chars_returns_one():
    assert shannon_entropy("ab") == 1.0


def test_high_entropy_random_string():
    # A random-looking hex string should have high entropy
    result = shannon_entropy("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
    assert result > 3.0


def test_low_entropy_repeated_pattern():
    result = shannon_entropy("abcabcabc")
    assert result < 2.0


def test_return_type_is_float():
    assert isinstance(shannon_entropy("test"), float)


def test_base64_string_has_expected_entropy():
    # Realistic base64 secret — should be in the 3.5-6.0 range
    result = shannon_entropy("dGhpcyBpcyBhIHNlY3JldCBrZXkgdmFsdWU=")
    assert 3.0 < result < 6.0
