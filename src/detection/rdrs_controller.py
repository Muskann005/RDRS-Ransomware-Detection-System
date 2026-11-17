
import argparse
import time
import yaml

from pathlib import Path
from datetime import datetime, timezone, timedelta

from src.detection.detection_engine import analyze_file_activity
from src.detection.threat_scoring import calculate_threat_score
from src.response.incident_response import handle_incident
from src.database.db_manager import (
    get_all_events,
    insert_processes
)
from src.monitoring.process_monitor import analyze_processes


PROJECT_DIR = Path(__file__).resolve().parents[2]
CONFIG_FILE = PROJECT_DIR / "config.yaml"

# Prevent repeated incident creation during one continuing burst.
_incident_active_for_burst = False

FILE_EVENT_TYPES = {
    "NEW FILE",
    "CREATED",
    "MODIFIED",
    "RENAMED",
    "MOVED",
    "DELETED"
}


def load_config():
    with CONFIG_FILE.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


def get_affected_files(window_seconds):
    """Get files affected during the current detection window."""

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=window_seconds)

    events = get_all_events()
    affected_files = set()

    for event in events:
        timestamp = event.get("timestamp")

        if not timestamp:
            continue

        try:
            event_time = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )

            if event_time.tzinfo is None:
                event_time = event_time.replace(tzinfo=timezone.utc)

            if cutoff <= event_time <= now:
                filepath = (
                    event.get("file_path")
                    or event.get("file")
                )

                if filepath:
                    affected_files.add(filepath)

        except (ValueError, TypeError, AttributeError):
            continue

    return sorted(affected_files)


def evaluate_detection(process_result=None):
    """
    Analyze the current file-event window, calculate its threat score,
    and create an incident only once during a continuing burst.
    """

    global _incident_active_for_burst

    config = load_config()

    window_seconds = config.get(
        "monitoring", {}
    ).get("analysis_window_seconds", 60)

    if process_result is None:
        process_result = {
            "cpu_spike": False,
            "unknown_process": False,
            "unknown_processes": []
        }

    print("\n[RDRS] Analyzing file activity...")

    detection_result = analyze_file_activity()

    print("Files modified:", detection_result["files_modified"])
    print("New files:", detection_result.get("new_files", 0))
    print("Files renamed:", detection_result["files_renamed"])
    print("Extension changes:", detection_result["extension_changes"])
    print("Average entropy:", detection_result["average_entropy"])
    print("Suspicious activity:", detection_result["suspicious"])

    score_result = calculate_threat_score(
        detection_result,
        cpu_spike=process_result.get("cpu_spike", False),
        unknown_process=process_result.get("unknown_process", False),
        save_to_database=True
    )

    print("Threat score:", score_result["score"])
    print("Threat level:", score_result["threat_level"])
    print("Reasons:", score_result["reasons"])

    if score_result["threat_level"] == "Critical":

        if not _incident_active_for_burst:
            print("\n[RDRS] New Critical burst detected.")

            affected_files = get_affected_files(window_seconds)

            incident_result = handle_incident(
                detection_result,
                score_result,
                affected_files=affected_files,
                suspect_process=process_result.get(
                    "unknown_processes", []
                )
            )

            if incident_result.get("incident_created"):
                _incident_active_for_burst = True

        else:
            print(
                "[RDRS] Incident response already performed "
                "for this continuing burst."
            )

    elif not detection_result.get("suspicious", False):
        # A clean window ends the previous suspicious burst.
        _incident_active_for_burst = False

    return {
        "detection": detection_result,
        "score": score_result
    }


def run_once():
    """Run one complete RDRS detection and process-monitoring cycle."""

    print("\n===================================")
    print(" RDRS - DETECTION AND RESPONSE")
    print("===================================")

    print("\n[1] Analyzing running processes...")

    process_result = analyze_processes()

    print("System CPU:", process_result["system_cpu_percent"], "%")
    print("CPU spike:", process_result["cpu_spike"])
    print(
        "Unknown process instances:",
        len(process_result["unknown_processes"])
    )

    print("\n[2] Saving process snapshots...")

    database_message = insert_processes(
        process_result["processes"]
    )

    print(database_message)

    print("\n[3] Evaluating file activity and threat score...")

    evaluation = evaluate_detection(process_result)

    print("\n===================================")
    print(" RDRS CYCLE COMPLETED")
    print("===================================")

    return {
        "detection": evaluation["detection"],
        "process": process_result,
        "score": evaluation["score"],
        "affected_files": get_affected_files(
            evaluation["detection"]["window_seconds"]
        )
    }


def get_latest_event_id(events=None):
    """Return the highest event ID currently stored in the database."""

    if events is None:
        events = get_all_events()

    return max(
        (event.get("id", 0) or 0 for event in events),
        default=0
    )


def run_continuously():
    """
    Run event-triggered file detection with periodic process monitoring.

    New file events are checked approximately once per second.
    Process monitoring retains the configured analysis-window interval.
    """

    config = load_config()

    interval = config.get(
        "monitoring", {}
    ).get("analysis_window_seconds", 60)

    if not isinstance(interval, (int, float)) or interval <= 0:
        interval = 60

    print("Starting RDRS continuous monitoring...")
    print("File-event polling interval: 1 second")
    print("Process-monitoring interval:", interval, "seconds")

    # Run the initial full cycle.
    initial_cycle = run_once()

    # Keep only the process-monitoring result.
    # run_once() returns a wrapper containing detection, process, score,
    # and affected_files. evaluate_detection() needs the nested process data.
    process_result = initial_cycle["process"]

    # Ignore historical events already stored before monitoring began.
    last_event_id = get_latest_event_id()

    last_process_check = time.monotonic()

    try:
        while True:
            time.sleep(1)

            events = get_all_events()

            new_events = [
                event for event in events
                if (event.get("id", 0) or 0) > last_event_id
            ]

            if new_events:
                last_event_id = max(
                    event.get("id", 0) or 0
                    for event in new_events
                )

                new_file_events = [
                    event for event in new_events
                    if (
                        event.get("event_type")
                        or event.get("event")
                        or ""
                    ).strip().upper() in FILE_EVENT_TYPES
                ]

                if new_file_events:
                    print(
                        "\n[RDRS] New file event detected. "
                        "Recalculating the sliding window."
                    )

                    evaluate_detection(process_result)

            # Keep process monitoring on its existing periodic schedule.
            if time.monotonic() - last_process_check >= interval:

                print("\n[RDRS] Process-monitoring cycle started.")

                process_result = analyze_processes()

                print(
                    "System CPU:",
                    process_result["system_cpu_percent"],
                    "%"
                )

                print(
                    "Unknown process instances:",
                    len(process_result["unknown_processes"])
                )

                print(
                    insert_processes(process_result["processes"])
                )

                evaluate_detection(process_result)

                last_process_check = time.monotonic()

    except KeyboardInterrupt:
        print("\nRDRS monitoring stopped safely.")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="RDRS Detection Controller"
    )

    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Run continuous detection monitoring"
    )

    args = parser.parse_args()

    if args.continuous:
        run_continuously()
    else:
        run_once()
