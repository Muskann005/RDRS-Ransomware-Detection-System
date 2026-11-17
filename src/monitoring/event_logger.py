
import json
from datetime import datetime, timezone
from pathlib import Path

from src.monitoring.logger_config import get_logger

LOG_FILE = Path("logs/events.json")


def save_event(event):
    """Save an event to the central JSON log."""

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    events = []

    if LOG_FILE.exists():
        with LOG_FILE.open("r", encoding="utf-8") as file:
            events = json.load(file)

    if not isinstance(events, list):
        raise ValueError("Event log must contain a JSON list.")

    events.append(event)

    with LOG_FILE.open("w", encoding="utf-8") as file:
        json.dump(events, file, indent=4)

    return event


def log_event(result):
    """Log entropy analysis events."""

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "module": result["module"],
        "input": result["input"],
        "entropy_score": result["entropy_score"],
        "status": result["status"],
        "alert": result["alert"]
    }

    save_event(event)

    get_logger("events").info(
        "Entropy event: module={}, input={}, status={}, entropy={}",
        event["module"],
        event["input"],
        event["status"],
        event["entropy_score"]
    )

    if event["alert"]:
        get_logger("alerts").warning(
            "Entropy alert: input={}, entropy={}",
            event["input"],
            event["entropy_score"]
        )

    get_logger("audit").info(
        "Entropy analysis completed for {}",
        event["input"]
    )

    return event


def log_file_event(result):
    """Log file monitoring events, including extensions."""

    filepath = Path(result["file"])
    event_type = result["event"]

    event = {
        "timestamp": result.get(
            "timestamp",
            datetime.now(timezone.utc).isoformat()
        ),
        "module": "File Monitoring",
        "file": str(filepath),
        "extension": result.get(
            "extension",
            filepath.suffix.lower()
        ),
        "event": event_type,
        "entropy_score": result.get("entropy_score"),
        "status": "change_detected",
        "alert": result.get(
            "alert",
            event_type in ("MODIFIED", "DELETED")
        )
    }

    save_event(event)

    get_logger("events").info(
        "File event: type={}, file={}, entropy={}",
        event_type,
        filepath,
        event["entropy_score"]
    )

    if event["alert"]:
        get_logger("alerts").warning(
            "File alert: type={}, file={}",
            event_type,
            filepath
        )

    get_logger("audit").info(
        "File monitoring recorded {} for {}",
        event_type,
        filepath
    )

    return event


def log_system(message):
    """Record system-level information."""
    get_logger("system").info(message)


def log_error(message):
    """Record application errors."""
    get_logger("errors").error(message)
