
import yaml
from pathlib import Path
from datetime import datetime, timezone, timedelta

from src.database.db_manager import get_all_events


PROJECT_DIR = Path(__file__).resolve().parents[2]
CONFIG_FILE = PROJECT_DIR / "config.yaml"


def load_config():
    """Load detection settings from config.yaml."""
    with CONFIG_FILE.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


def parse_timestamp(value):
    """Convert an ISO timestamp into a timezone-aware datetime."""
    try:
        if isinstance(value, datetime):
            timestamp = value
        else:
            timestamp = datetime.fromisoformat(
                str(value).replace("Z", "+00:00")
            )

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        return timestamp.astimezone(timezone.utc)

    except (TypeError, ValueError):
        return None


def normalize_file_path(file_path):
    """Normalize a file path for consistent duplicate detection."""
    if not file_path:
        return None

    return str(file_path).replace("\\", "/").strip().rstrip("/")


def analyze_file_activity(events=None, now=None):
    """
    Analyze file activity within a rolling time window.

    Detect:
    - Unique files modified within the analysis window
    - Mass file renaming
    - File extension changes
    - High average entropy of newly written or modified files
    """

    config = load_config()

    monitoring = config.get("monitoring", {})
    detection = config.get("detection", {})

    window_seconds = monitoring.get(
        "analysis_window_seconds", 60
    )

    max_modified = detection.get(
        "max_modified_files", 10
    )

    max_renamed = detection.get(
        "max_renamed_files", 5
    )

    max_extension_changes = detection.get(
        "max_extension_changes", 3
    )

    entropy_threshold = detection.get(
        "high_entropy_threshold", 7.0
    )

    if now is None:
        now = datetime.now(timezone.utc)
    else:
        now = parse_timestamp(now)

        if now is None:
            raise ValueError("Invalid analysis timestamp")

    cutoff = now - timedelta(seconds=window_seconds)

    if events is None:
        events = get_all_events()

    recent_events = []

    # Keep only events inside the rolling analysis window.
    for event in events:

        timestamp = parse_timestamp(event.get("timestamp"))

        if timestamp and cutoff <= timestamp <= now:
            recent_events.append(event)

    modified_files = set()
    new_file_count = 0
    renamed_count = 0
    extension_changes = 0

    entropy_values = []

    # Analyze the event stream.
    for event in recent_events:

        event_type = (
            event.get("event_type")
            or event.get("event")
            or ""
        ).strip().upper()

        # Count unique modified files, not repeated modification events.
        if event_type == "MODIFIED":

            file_path = normalize_file_path(
                event.get("file_path")
                or event.get("file")
            )

            if file_path:
                modified_files.add(file_path)

        if event_type in ("NEW FILE", "CREATED"):
            new_file_count += 1

        if event_type in ("RENAMED", "MOVED"):

            renamed_count += 1

            old_path = (
                event.get("input_data")
                or event.get("input")
            )

            new_path = (
                event.get("file_path")
                or event.get("file")
            )

            if old_path and new_path:

                old_extension = Path(
                    str(old_path).replace("\\", "/")
                ).suffix.lower()

                new_extension = Path(
                    str(new_path).replace("\\", "/")
                ).suffix.lower()

                if old_extension != new_extension:
                    extension_changes += 1

        # Preserve the existing entropy calculation.
        if event_type in (
            "NEW FILE",
            "CREATED",
            "MODIFIED"
        ):

            entropy = event.get("entropy_score")

            if (
                isinstance(entropy, (int, float))
                and not isinstance(entropy, bool)
            ):
                entropy_values.append(float(entropy))

    # Count unique modified files in the analysis window.
    modified_count = len(modified_files)

    # Calculate average entropy of files with available entropy readings.
    average_entropy = (
        sum(entropy_values) / len(entropy_values)
        if entropy_values
        else 0.0
    )

    average_entropy = round(average_entropy, 4)

    # Compare activity counters with configured thresholds.
    reasons = []

    if modified_count > max_modified:
        reasons.append(
            "Rapid file modifications detected"
        )

    if renamed_count > max_renamed:
        reasons.append(
            "Mass file renaming detected"
        )

    if extension_changes > max_extension_changes:
        reasons.append(
            "Multiple file extension changes detected"
        )

    if (
        entropy_values
        and average_entropy >= entropy_threshold
    ):
        reasons.append(
            "High average file entropy detected"
        )

    result = {
        "timestamp": now.isoformat(),
        "window_seconds": window_seconds,
        "files_modified": modified_count,
        "new_files": new_file_count,
        "files_renamed": renamed_count,
        "extension_changes": extension_changes,
        "average_entropy": average_entropy,
        "high_entropy_threshold": entropy_threshold,
        "suspicious": bool(reasons),
        "reasons": reasons
    }

    return result


if __name__ == "__main__":

    result = analyze_file_activity()

    print("\nRDRS DETECTION ENGINE")
    print("---------------------")

    for key, value in result.items():
        print(f"{key}: {value}")
