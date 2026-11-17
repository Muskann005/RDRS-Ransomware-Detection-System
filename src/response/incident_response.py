
import shutil
import yaml

from pathlib import Path
from datetime import datetime, timezone

from src.database.db_manager import (
    insert_incident,
    insert_alert
)
from src.monitoring.logger_config import get_logger


# Project directories
PROJECT_DIR = Path(__file__).resolve().parents[2]

CONFIG_FILE = PROJECT_DIR / "config.yaml"

SANDBOX_DIR = PROJECT_DIR / "data" / "sandbox"

QUARANTINE_DIR = PROJECT_DIR / "data" / "quarantine"


def load_config():
    """Load response configuration."""

    with CONFIG_FILE.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


def copy_evidence_to_quarantine(affected_files):
    """
    Safely copy evidence files from the dedicated sandbox.
    Original files are never modified or deleted.
    """

    SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    incident_folder = QUARANTINE_DIR / f"incident_{timestamp}"
    incident_folder.mkdir(parents=True, exist_ok=True)

    copied_files = []
    skipped_files = []

    for file_path in affected_files:

        try:
            source = Path(file_path).resolve()

            # Only allow files inside the dedicated sandbox
            if not source.is_relative_to(SANDBOX_DIR.resolve()):
                skipped_files.append({
                    "file": str(file_path),
                    "reason": "File is outside the RDRS sandbox"
                })
                continue

            if not source.is_file():
                skipped_files.append({
                    "file": str(file_path),
                    "reason": "File does not exist"
                })
                continue

            destination = incident_folder / source.name

            # Avoid overwriting an existing evidence file
            counter = 1

            while destination.exists():
                destination = incident_folder / (
                    f"{source.stem}_{counter}{source.suffix}"
                )
                counter += 1

            shutil.copy2(source, destination)

            copied_files.append({
                "original": str(source),
                "quarantine": str(destination)
            })

        except (OSError, ValueError) as error:
            skipped_files.append({
                "file": str(file_path),
                "reason": str(error)
            })

    return {
        "quarantine_folder": str(incident_folder),
        "copied_files": copied_files,
        "skipped_files": skipped_files
    }


def handle_incident(
    detection_result,
    score_result,
    affected_files=None,
    suspect_process=None
):
    """
    Create a Critical incident, save its records, copy evidence,
    and write dedicated alert and audit log entries.

    Process termination is never performed.
    Evidence copying is restricted to the RDRS sandbox.
    """

    config = load_config()

    simulation = config.get("simulation", {}).get(
        "enabled", True
    )

    affected_files = affected_files or []
    suspect_process = (
        suspect_process if suspect_process is not None else {}
    )

    score = score_result.get("score", 0)
    threat_level = score_result.get("threat_level", "Normal")

    print("\nRDRS INCIDENT RESPONSE")
    print("----------------------")

    print("Threat level:", threat_level)
    print("Threat score:", score)
    print("Simulation mode:", simulation)

    # Only Critical threats create incidents
    if threat_level != "Critical":

        print("No Critical threat detected. Incident not created.")

        return {
            "incident_created": False,
            "message": "Threat level is not Critical"
        }

    timestamp = datetime.now(timezone.utc).isoformat()

    # Copy evidence safely
    quarantine_result = copy_evidence_to_quarantine(
        affected_files
    )

    copied_files = quarantine_result["copied_files"]
    skipped_files = quarantine_result["skipped_files"]

    # Prepare incident information
    incident = {
        "timestamp": timestamp,
        "severity": "Critical",
        "score": score,
        "summary": "Critical threat detected by RDRS",
        "affected_files": affected_files,
        "suspect_process": suspect_process,
        "status": "open",
        "quarantine_path": quarantine_result["quarantine_folder"]
    }

    # Store incident in database
    incident_status = insert_incident(incident)

    # Store security alert in database
    alert_message = (
        f"RDRS detected a Critical threat. "
        f"Score: {score}. "
        f"Evidence copied: {len(copied_files)}"
    )

    alert = {
        "timestamp": timestamp,
        "severity": "Critical",
        "message": alert_message,
        "score": score,
        "status": "open"
    }

    alert_status = insert_alert(alert)

    # Write dedicated Critical incident alert log
    get_logger("alerts").critical(
        "Critical incident created: score={}, affected_files={}, "
        "evidence_copied={}, evidence_skipped={}, quarantine={}",
        score,
        len(affected_files),
        len(copied_files),
        len(skipped_files),
        quarantine_result["quarantine_folder"]
    )

    # Write dedicated incident audit log
    get_logger("audit").info(
        "Incident response completed: timestamp={}, severity={}, "
        "score={}, incident_status={}, alert_status={}, "
        "affected_files={}, evidence_copied={}, evidence_skipped={}, "
        "simulation_mode={}",
        timestamp,
        threat_level,
        score,
        incident_status,
        alert_status,
        len(affected_files),
        len(copied_files),
        len(skipped_files),
        simulation
    )

    # Simulation mode: never terminate processes
    if simulation:
        response_action = (
            "Simulation mode enabled. "
            "Process termination was not performed."
        )
    else:
        response_action = (
            "Automatic process termination is disabled "
            "in this implementation."
        )

    result = {
        "incident_created": True,
        "incident_status": incident_status,
        "alert_status": alert_status,
        "threat_score": score,
        "threat_level": threat_level,
        "quarantine": quarantine_result,
        "response_action": response_action
    }

    print("\nIncident created successfully.")
    print("Evidence copied:", len(copied_files))
    print("Evidence skipped:", len(skipped_files))
    print("Alert:", alert_status)
    print("Response:", response_action)

    return result


if __name__ == "__main__":

    # Safe demonstration data
    demo_detection = {
        "files_modified": 12,
        "files_renamed": 6,
        "extension_changes": 6,
        "average_entropy": 7.8,
        "suspicious": True,
        "reasons": [
            "Rapid file modifications detected",
            "Mass file renaming detected",
            "High average file entropy detected"
        ]
    }

    demo_score = {
        "score": 95,
        "threat_level": "Critical",
        "reasons": [
            "Rapid file modifications (+40)",
            "Mass file renaming (+30)",
            "High file entropy (+25)"
        ]
    }

    demo_process = {
        "name": "RDRS_TEST_PROCESS",
        "pid": 99999
    }

    result = handle_incident(
        detection_result=demo_detection,
        score_result=demo_score,
        affected_files=[],
        suspect_process=demo_process
    )

    print("\nFinal result:")
    print(result)
