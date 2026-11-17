
from src.entropy_detector import (
    calculate_entropy,
    analyze_file_entropy,
    detect_suspicious_entropy,
    DEFAULT_THRESHOLD,
    SAMPLE_SIZE,
)


# calculate_entropy() tests

def test_empty_string():
    assert calculate_entropy("") == 0.0


def test_empty_bytes():
    assert calculate_entropy(b"") == 0.0


def test_repeated_string():
    assert calculate_entropy("aaaa") == 0.0


def test_binary_string():
    assert calculate_entropy("0101") == 1.0


def test_binary_bytes():
    assert calculate_entropy(b"\x00\x01") == 1.0


def test_entropy_is_positive():
    assert calculate_entropy("abcdef") > 0


def test_high_entropy_string():
    assert calculate_entropy("aB9$xK2@mP7#qL5!vN8&zR4") > 4.5


def test_unicode_string():
    assert calculate_entropy("hello नमस्ते") > 0


def test_entropy_is_rounded():
    result = calculate_entropy("abc")
    assert result == round(result, 4)


# analyze_file_entropy() tests

def test_analyze_normal_file(tmp_path):
    file_path = tmp_path / "normal.txt"
    file_path.write_text("aaaaaaaaaa", encoding="utf-8")

    result = analyze_file_entropy(file_path)

    assert result["entropy"] == 0.0
    assert result["status"] == "normal"
    assert result["alert"] is False
    assert result["error"] is None


def test_analyze_suspicious_file(tmp_path):
    file_path = tmp_path / "suspicious.txt"
    file_path.write_text(
        "aB9$xK2@mP7#qL5!vN8&zR4",
        encoding="utf-8"
    )

    result = analyze_file_entropy(file_path)

    assert result["entropy"] > DEFAULT_THRESHOLD
    assert result["status"] == "suspicious"
    assert result["alert"] is True
    assert result["error"] is None


def test_analyze_empty_file(tmp_path):
    file_path = tmp_path / "empty.txt"
    file_path.write_bytes(b"")

    result = analyze_file_entropy(file_path)

    assert result["entropy"] == 0.0
    assert result["status"] == "normal"
    assert result["alert"] is False


def test_analyze_missing_file(tmp_path):
    file_path = tmp_path / "missing.txt"

    result = analyze_file_entropy(file_path)

    assert result["entropy"] is None
    assert result["status"] == "error"
    assert result["alert"] is False
    assert result["error"] is not None


def test_analyze_only_first_64kb(tmp_path):
    file_path = tmp_path / "sample_limit.txt"

    # The first 64 KB contain repeated bytes.
    # High-entropy data after that should not be analyzed.
    file_path.write_bytes(
        (b"a" * SAMPLE_SIZE) +
        b"aB9$xK2@mP7#qL5!vN8&zR4"
    )

    result = analyze_file_entropy(file_path)

    assert result["entropy"] == 0.0
    assert result["status"] == "normal"


# detect_suspicious_entropy() tests

def test_detect_normal_entropy():
    result = detect_suspicious_entropy("aaaaaaaa")

    assert result["entropy"] == 0.0
    assert result["status"] == "normal"
    assert result["alert"] is False


def test_detect_high_entropy():
    result = detect_suspicious_entropy(
        "aB9$xK2@mP7#qL5!vN8&zR4"
    )

    assert result["entropy"] > DEFAULT_THRESHOLD
    assert result["status"] == "suspicious"
    assert result["alert"] is True


def test_detect_with_custom_threshold():
    result = detect_suspicious_entropy(
        "abcdef",
        threshold=0.5
    )

    assert result["status"] == "suspicious"
    assert result["alert"] is True


def test_entropy_equal_to_threshold_is_normal():
    entropy = calculate_entropy("0101")

    result = detect_suspicious_entropy(
        "0101",
        threshold=entropy
    )

    assert result["status"] == "normal"
    assert result["alert"] is False
