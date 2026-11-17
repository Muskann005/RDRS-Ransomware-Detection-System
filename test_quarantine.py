
import hashlib
from pathlib import Path

from src.response.incident_response import (
    copy_evidence_to_quarantine
)


PROJECT_DIR = Path(__file__).resolve().parent

TEST_FILE = (
    PROJECT_DIR
    / "data"
    / "sandbox"
    / "rdrs_quarantine_test.txt"
)


def calculate_hash(file_path):
    """Calculate SHA-256 hash of a file."""

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


print("\nRDRS QUARANTINE TEST")
print("====================")

# Check original file
if not TEST_FILE.is_file():
    print("ERROR: Test file not found.")
    raise SystemExit(1)

print("\nOriginal file:", TEST_FILE)

# Calculate original hash
original_hash = calculate_hash(TEST_FILE)

print("Original SHA-256:", original_hash)

# Copy evidence to quarantine
result = copy_evidence_to_quarantine([str(TEST_FILE)])

print("\nQuarantine result:")
print(result)

# Verify copied file
if not result["copied_files"]:
    print("\nFAILED: Evidence was not copied.")
    raise SystemExit(1)

copied_file = Path(
    result["copied_files"][0]["quarantine"]
)

if not copied_file.is_file():
    print("\nFAILED: Quarantine file does not exist.")
    raise SystemExit(1)

copied_hash = calculate_hash(copied_file)

print("\nCopied SHA-256:", copied_hash)

# Compare hashes
print("\nHASH VERIFICATION")

if original_hash == copied_hash:
    print("PASSED: Original and copied files match.")
else:
    print("FAILED: File hashes do not match.")

# Verify original still exists
if TEST_FILE.is_file():
    print("PASSED: Original file remains untouched.")
else:
    print("FAILED: Original file is missing.")

print("\nQuarantine test completed.")
