

import math
from collections import Counter
from pathlib import Path


# Default threshold; can later be loaded from config.yaml
DEFAULT_THRESHOLD = 4.5

# Analyze the first 64 KB of a file
SAMPLE_SIZE = 64 * 1024


def calculate_entropy(data):
    """Calculate Shannon entropy of bytes or text."""

    if not data:
        return 0.0

    if isinstance(data, str):
        data = data.encode("utf-8")

    length = len(data)
    frequencies = Counter(data)

    entropy = 0.0

    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def analyze_file_entropy(filepath):
    """Calculate entropy from the first 64 KB of a file."""

    path = Path(filepath)

    try:
        with path.open("rb") as file:
            data = file.read(SAMPLE_SIZE)

        entropy = calculate_entropy(data)

        return {
            "file": str(path),
            "entropy": entropy,
            "status": (
                "suspicious"
                if entropy > DEFAULT_THRESHOLD
                else "normal"
            ),
            "alert": entropy > DEFAULT_THRESHOLD,
            "error": None
        }

    except OSError as error:

        return {
            "file": str(path),
            "entropy": None,
            "status": "error",
            "alert": False,
            "error": str(error)
        }


def detect_suspicious_entropy(data, threshold=DEFAULT_THRESHOLD):
    """Analyze text or bytes and detect high entropy."""

    entropy = calculate_entropy(data)

    return {
        "entropy": entropy,
        "status": (
            "suspicious" if entropy > threshold else "normal"
        ),
        "alert": entropy > threshold
    }


if __name__ == "__main__":

    sample = "aB9$xK2@mP7#qL5!vN8&zR4"

    print("Text entropy test:")
    print(detect_suspicious_entropy(sample))

    test_file = Path("config") / "entropy_test.txt"

    if test_file.exists():
        print("\nFile entropy test:")
        print(analyze_file_entropy(test_file))
    else:
        print("\nCreate config/entropy_test.txt to test file entropy.")
