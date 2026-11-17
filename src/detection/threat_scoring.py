
from pathlib import Path
import yaml
from datetime import datetime, timezone

from src.database.db_manager import insert_score


PROJECT_DIR = Path(__file__).resolve().parents[2]
CONFIG_FILE = PROJECT_DIR / "config.yaml"


def load_config():
    with CONFIG_FILE.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def calculate_threat_score(
    detection_result,
    cpu_spike=False,
    unknown_process=False,
    save_to_database=True
):
    """
    Calculate RDRS threat score and optionally save it to SQLite.
    """

    config = load_config()

    weights = config.get("threat_scoring", {})
    detection = config.get("detection", {})

    score = 0
    reasons = []

    # Rapid file modifications
    if detection_result.get("files_modified", 0) > detection.get(
        "max_modified_files", 10
    ):
        weight = weights.get("rapid_encryption", 40)
        score += weight
        reasons.append(f"Rapid file modifications (+{weight})")

    # Mass file renaming
    if detection_result.get("files_renamed", 0) > detection.get(
        "max_renamed_files", 5
    ):
        weight = weights.get("mass_rename", 30)
        score += weight
        reasons.append(f"Mass file renaming (+{weight})")

    # High entropy
    entropy = detection_result.get("average_entropy", 0)
    threshold = detection.get("high_entropy_threshold", 7.0)

    if entropy >= threshold:
        weight = weights.get("high_entropy", 25)
        score += weight
        reasons.append(f"High file entropy (+{weight})")

    # CPU spike
    if cpu_spike:
        weight = weights.get("cpu_spike", 15)
        score += weight
        reasons.append(f"CPU spike (+{weight})")

    # Unknown process
    if unknown_process:
        weight = weights.get("unknown_process", 10)
        score += weight
        reasons.append(f"Unknown process (+{weight})")

    # Maximum score is 100
    score = min(score, 100)

    # Determine threat level
    if score >= 70:
        threat_level = "Critical"
    elif score > 40:
        threat_level = "Warning"
    else:
        threat_level = "Normal"

    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "threat_level": threat_level,
        "reasons": reasons
    }

    # Save score in SQLite through SQLAlchemy
    if save_to_database:
        result["database_status"] = insert_score(result)

    return result


if __name__ == "__main__":
    from src.detection.detection_engine import analyze_file_activity

    detection_result = analyze_file_activity()

    result = calculate_threat_score(
        detection_result,
        cpu_spike=False,
        unknown_process=False
    )

    print("\nRDRS THREAT SCORING ENGINE")
    print("-------------------------")

    for key, value in result.items():
        print(f"{key}: {value}")
