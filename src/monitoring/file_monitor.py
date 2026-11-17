
import os
import json
import hashlib
import argparse
import threading

from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

import yaml

from watchdog.observers.polling import PollingObserver
from watchdog.events import FileSystemEventHandler

from src.database.db_manager import (
    initialize_database,
    insert_event
)

from src.entropy_detector import analyze_file_entropy
from src.monitoring.event_logger import (
    log_file_event,
    log_system,
    log_error
)


PROJECT_DIR = Path(__file__).resolve().parents[2]
CONFIG_FILE = PROJECT_DIR / "config.yaml"
BASELINE_FILE = PROJECT_DIR / "reports" / "file_baseline.json"

EVENT_COUNT = 0
EVENT_LOCK = threading.Lock()


def load_config():
    """Load monitoring settings from config.yaml."""

    if CONFIG_FILE.exists():
        with CONFIG_FILE.open("r", encoding="utf-8") as file:
            config = yaml.safe_load(file) or {}
    else:
        config = {}

    monitoring = config.get("monitoring", {})
    watch_directory = monitoring.get(
        "watch_directory",
        "data/sandbox"
    )

    return PROJECT_DIR / watch_directory


MONITOR_DIR = load_config()


def get_timestamp():
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------
# FILE UTILITIES
# --------------------------------------------------

def calculate_file_hash(filepath):
    """Calculate SHA256 hash of a file."""

    sha256 = hashlib.sha256()

    with open(filepath, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def get_entropy(filepath):
    """Calculate file entropy safely."""

    try:
        result = analyze_file_entropy(filepath)
        return result.get("entropy"), result.get("status")

    except (OSError, PermissionError) as error:
        message = f"Entropy error for {filepath}: {error}"
        print(f"[ENTROPY ERROR] {message}")
        log_error(message)
        return None, "unavailable"


def save_baseline(current_files):
    BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)

    with BASELINE_FILE.open("w", encoding="utf-8") as file:
        json.dump(current_files, file, indent=4)


# --------------------------------------------------
# EVENT RECORDING
# --------------------------------------------------

def record_event(record):
    """Save events to SQLite and JSON logging."""

    global EVENT_COUNT

    record["extension"] = Path(record["file"]).suffix.lower()

    insert_event(record)
    log_file_event(record)

    with EVENT_LOCK:
        EVENT_COUNT += 1
        current_count = EVENT_COUNT

    print(
        f"[EVENT COUNT] {current_count} | "
        f"[FILE EVENT] {record['event']}: {record['file']}"
    )

    return record


# --------------------------------------------------
# BASELINE SCANNING
# --------------------------------------------------

def scan_files():
    """Detect new, modified, deleted and renamed files."""

    MONITOR_DIR.mkdir(parents=True, exist_ok=True)
    BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)

    initialize_database()

    log_system("RDRS baseline file scan started.")

    current_files = {}

    for root, dirs, files in os.walk(MONITOR_DIR):
        for filename in files:
            filepath = Path(root) / filename

            try:
                current_files[str(filepath)] = calculate_file_hash(filepath)

            except OSError as error:
                message = f"Scan error for {filepath}: {error}"
                print(f"[SCAN ERROR] {message}")
                log_error(message)

    if BASELINE_FILE.exists():
        try:
            with BASELINE_FILE.open("r", encoding="utf-8") as file:
                previous_files = json.load(file)

        except (OSError, json.JSONDecodeError) as error:
            log_error(f"Could not read previous baseline: {error}")
            previous_files = {}
    else:
        previous_files = {}

    changes = []

    # Detect modified files
    for filepath, file_hash in current_files.items():
        if filepath in previous_files:
            if previous_files[filepath] != file_hash:
                changes.append({
                    "event": "MODIFIED",
                    "file": filepath
                })

    deleted_paths = [
        path for path in previous_files
        if path not in current_files
    ]

    new_paths = [
        path for path in current_files
        if path not in previous_files
    ]

    # Detect possible renames using matching hashes
    old_hashes = defaultdict(list)
    new_hashes = defaultdict(list)

    for path in deleted_paths:
        old_hashes[previous_files[path]].append(path)

    for path in new_paths:
        new_hashes[current_files[path]].append(path)

    matched_old = set()
    matched_new = set()

    for file_hash, old_list in old_hashes.items():
        new_list = new_hashes.get(file_hash, [])

        if len(old_list) == 1 and len(new_list) == 1:
            old_path = old_list[0]
            new_path = new_list[0]

            changes.append({
                "event": "RENAMED",
                "file": new_path,
                "old_file": old_path
            })

            matched_old.add(old_path)
            matched_new.add(new_path)

    # Detect remaining new files
    for filepath in new_paths:
        if filepath not in matched_new:
            changes.append({
                "event": "NEW FILE",
                "file": filepath
            })

    # Detect remaining deleted files
    for filepath in deleted_paths:
        if filepath not in matched_old:
            changes.append({
                "event": "DELETED",
                "file": filepath
            })

    timestamp = get_timestamp()

    save_baseline(current_files)

    for change in changes:
        filepath = change["file"]
        entropy_score = None
        entropy_status = None

        if change["event"] in ("NEW FILE", "MODIFIED"):
            entropy_score, entropy_status = get_entropy(filepath)

        record = {
            "timestamp": timestamp,
            "module": "File Monitoring",
            "event": change["event"],
            "input": change.get("old_file"),
            "file": filepath,
            "entropy_score": entropy_score,
            "status": "change_detected",
            "alert": entropy_status == "suspicious"
        }

        record_event(record)

    log_system(
        f"RDRS baseline scan completed. Changes detected: {len(changes)}"
    )

    return {
        "timestamp": timestamp,
        "changes_detected": changes,
        "total_changes": len(changes)
    }


# --------------------------------------------------
# REAL-TIME FILE MONITORING
# --------------------------------------------------

class RDRSFileHandler(FileSystemEventHandler):
    """Handle real-time filesystem events."""

    def process_event(self, filepath, event_type, old_filepath=None):

        path = Path(filepath)

        if event_type in ("NEW FILE", "MODIFIED") and not path.is_file():
            return

        relative_path = os.path.relpath(path, PROJECT_DIR)

        old_relative_path = (
            os.path.relpath(old_filepath, PROJECT_DIR)
            if old_filepath else None
        )

        entropy_score = None
        entropy_status = None

        if event_type in ("NEW FILE", "MODIFIED"):
            entropy_score, entropy_status = get_entropy(path)

        record = {
            "timestamp": get_timestamp(),
            "module": "File Monitoring",
            "event": event_type,
            "input": old_relative_path,
            "file": relative_path,
            "entropy_score": entropy_score,
            "status": "change_detected",
            "alert": entropy_status == "suspicious"
        }

        try:
            record_event(record)

        except Exception as error:
            message = f"File event processing error: {error}"
            print(f"[LOGGING ERROR] {message}")
            log_error(message)
            return

        if entropy_score is not None:
            print(
                f"[ENTROPY] Score: {entropy_score} | "
                f"Status: {entropy_status}"
            )

    def on_created(self, event):
        if not event.is_directory:
            self.process_event(event.src_path, "NEW FILE")

    def on_modified(self, event):
        if not event.is_directory:
            self.process_event(event.src_path, "MODIFIED")

    def on_deleted(self, event):
        if not event.is_directory:
            self.process_event(event.src_path, "DELETED")

    def on_moved(self, event):
        if not event.is_directory:
            self.process_event(
                event.dest_path,
                "RENAMED",
                old_filepath=event.src_path
            )


# --------------------------------------------------
# START MONITORING
# --------------------------------------------------

def run_realtime_monitor():
    """Start continuous filesystem monitoring using polling."""

    MONITOR_DIR.mkdir(parents=True, exist_ok=True)
    initialize_database()

    observer = PollingObserver(timeout=1)
    handler = RDRSFileHandler()

    observer.schedule(
        handler,
        str(MONITOR_DIR),
        recursive=True
    )

    observer.start()

    startup_message = (
        f"RDRS real-time monitoring started. "
        f"Directory: {MONITOR_DIR}"
    )

    print("\nRDRS Real-Time File Monitoring Started")
    print(f"Monitoring directory: {MONITOR_DIR}")
    print("Observer: PollingObserver (1-second interval)")
    print("Detecting: CREATE, MODIFY, DELETE, RENAME and ENTROPY")
    print("Logging: SQLite, JSON and rotating log files")
    print("Press Ctrl+C to stop monitoring.\n")

    log_system(startup_message)

    try:
        while observer.is_alive():
            observer.join(1)

    except KeyboardInterrupt:
        print("\nStopping file monitoring...")
        log_system("RDRS monitoring stopped by user.")

    except Exception as error:
        message = f"Monitoring runtime error: {error}"
        log_error(message)
        raise

    finally:
        observer.stop()
        observer.join()

        log_system(
            f"RDRS monitoring shutdown completed. "
            f"Total events recorded: {EVENT_COUNT}"
        )

        print(f"Total events recorded: {EVENT_COUNT}")
        print("File monitoring stopped.")


# --------------------------------------------------
# MAIN
# --------------------------------------------------

if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--watch",
        action="store_true",
        help="Start real-time monitoring"
    )

    args = parser.parse_args()

    if args.watch:
        run_realtime_monitor()
    else:
        print(json.dumps(scan_files(), indent=4))
