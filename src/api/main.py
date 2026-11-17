
from pathlib import Path
from datetime import datetime, timezone
import csv
import io
import json
import threading

import yaml

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import text

from src.database.db_manager import (
    engine,
    initialize_database,
    insert_event,
    get_all_events,
    get_all_processes,
    get_all_scores,
    get_all_alerts,
    get_all_incidents,
)

from src.detection.entropy_analysis import analyze_data
from src.detection.rdrs_controller import run_continuously
from src.monitoring.event_logger import log_event
from src.monitoring.file_monitor import MONITOR_DIR, run_realtime_monitor


# ==========================================================
# APPLICATION CONFIGURATION
# ==========================================================

PROJECT_DIR = Path(__file__).resolve().parents[2]
CONFIG_FILE = PROJECT_DIR / "config.yaml"
DASHBOARD_DIR = PROJECT_DIR / "src" / "dashboard" / "static"

app = FastAPI(
    title="RDRS API",
    description="Ransomware Detection and Response System API",
    version="1.0.0",
)

initialize_database()

# File-monitor status
file_monitor_state = {
    "running": False,
    "error": None,
    "directory": str(MONITOR_DIR),
}

file_monitor_thread = None
file_monitor_lock = threading.Lock()

# Continuous-detection status
detection_monitor_state = {
    "running": False,
    "error": None,
    "interval_seconds": None,
}

detection_monitor_thread = None
detection_monitor_lock = threading.Lock()


# ==========================================================
# CONFIGURATION HELPERS
# ==========================================================

def load_config():
    if not CONFIG_FILE.exists():
        raise HTTPException(
            status_code=500,
            detail="Configuration file not found",
        )

    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as file:
            return yaml.safe_load(file) or {}

    except yaml.YAMLError as error:
        raise HTTPException(
            status_code=500,
            detail=f"Invalid configuration file: {error}",
        )


def update_config(settings):
    """Update approved settings without replacing other configuration."""

    if not isinstance(settings, dict) or not settings:
        raise HTTPException(
            status_code=400,
            detail="Provide a non-empty settings object",
        )

    allowed_settings = {
        "monitoring": {
            "watch_directory",
            "analysis_window_seconds",
        },
        "detection": {
            "max_modified_files",
            "max_renamed_files",
            "max_extension_changes",
            "high_entropy_threshold",
            "suspicious_entropy_threshold",
        },
        "threat_scoring": {
            "rapid_encryption",
            "mass_rename",
            "high_entropy",
            "cpu_spike",
            "unknown_process",
        },
        "process_monitoring": {
            "cpu_spike_threshold",
            "trusted_processes",
            "process_sample_interval",
        },
        "simulation": {
            "enabled",
        },
    }

    config = load_config()

    for section, values in settings.items():
        if section not in allowed_settings:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported configuration section: {section}",
            )

        if not isinstance(values, dict):
            raise HTTPException(
                status_code=400,
                detail=f"{section} must contain an object",
            )

        config.setdefault(section, {})

        for key, value in values.items():
            if key not in allowed_settings[section]:
                raise HTTPException(
                    status_code=400,
                    detail=f"Unsupported setting: {section}.{key}",
                )

            if key == "enabled":
                if not isinstance(value, bool):
                    raise HTTPException(
                        status_code=400,
                        detail="simulation.enabled must be true or false",
                    )

            elif key == "watch_directory":
                if not isinstance(value, str) or not value.strip():
                    raise HTTPException(
                        status_code=400,
                        detail="watch_directory must be a non-empty string",
                    )

            elif key == "trusted_processes":
                if (
                    not isinstance(value, list)
                    or not all(
                        isinstance(item, str) and item.strip()
                        for item in value
                    )
                ):
                    raise HTTPException(
                        status_code=400,
                        detail="trusted_processes must be a list of names",
                    )

            else:
                if (
                    isinstance(value, bool)
                    or not isinstance(value, (int, float))
                    or value < 0
                ):
                    raise HTTPException(
                        status_code=400,
                        detail=f"{key} must be a non-negative number",
                    )

            config[section][key] = value

    try:
        with CONFIG_FILE.open("w", encoding="utf-8") as file:
            yaml.safe_dump(
                config,
                file,
                sort_keys=False,
                allow_unicode=True,
            )

    except OSError as error:
        raise HTTPException(
            status_code=500,
            detail=f"Could not save configuration: {error}",
        )

    return config


# ==========================================================
# FILE MONITOR WORKER
# ==========================================================

def _file_monitor_worker():
    """Run the existing file monitor in a background thread."""

    try:
        with file_monitor_lock:
            file_monitor_state["running"] = True
            file_monitor_state["error"] = None

        run_realtime_monitor()

    except Exception as error:
        with file_monitor_lock:
            file_monitor_state["error"] = str(error)

        print(f"[RDRS FILE MONITOR ERROR] {error}")

    finally:
        with file_monitor_lock:
            file_monitor_state["running"] = False


# ==========================================================
# CONTINUOUS DETECTION WORKER
# ==========================================================

def _detection_worker():
    """Run continuous detection in a background thread."""

    try:
        with detection_monitor_lock:
            detection_monitor_state["running"] = True
            detection_monitor_state["error"] = None

        run_continuously()

    except Exception as error:
        with detection_monitor_lock:
            detection_monitor_state["error"] = str(error)

        print(f"[RDRS DETECTION ERROR] {error}")

    finally:
        with detection_monitor_lock:
            detection_monitor_state["running"] = False


# ==========================================================
# START MONITORING
# ==========================================================

def start_file_monitoring():
    """Start real-time file monitoring."""

    global file_monitor_thread

    if (
        file_monitor_thread is not None
        and file_monitor_thread.is_alive()
    ):
        return

    file_monitor_thread = threading.Thread(
        target=_file_monitor_worker,
        name="rdrs-file-monitor",
        daemon=True,
    )

    file_monitor_thread.start()

    print("[RDRS] File-monitor startup requested.")


def start_detection_monitoring():
    """Start continuous detection automatically."""

    global detection_monitor_thread

    if (
        detection_monitor_thread is not None
        and detection_monitor_thread.is_alive()
    ):
        return

    config = load_config()

    interval = config.get(
        "monitoring", {}
    ).get("analysis_window_seconds", 60)

    with detection_monitor_lock:
        detection_monitor_state["interval_seconds"] = interval

    detection_monitor_thread = threading.Thread(
        target=_detection_worker,
        name="rdrs-detection-monitor",
        daemon=True,
    )

    detection_monitor_thread.start()

    print("[RDRS] Continuous detection startup requested.")


@app.on_event("startup")
def startup_event():
    """Start both monitoring services when FastAPI launches."""

    start_file_monitoring()
    start_detection_monitoring()


# ==========================================================
# DASHBOARD STATIC FILES
# ==========================================================

app.mount(
    "/static",
    StaticFiles(directory=str(DASHBOARD_DIR)),
    name="static",
)


@app.get("/dashboard", include_in_schema=False)
def dashboard():
    index_file = DASHBOARD_DIR / "index.html"

    if not index_file.exists():
        raise HTTPException(
            status_code=404,
            detail="Dashboard index.html not found",
        )

    return FileResponse(index_file)


# ==========================================================
# REQUEST MODELS
# ==========================================================

class ScanRequest(BaseModel):
    data: str


# ==========================================================
# HOME ENDPOINT
# ==========================================================

@app.get("/")
def home():
    return {
        "message": "RDRS API is running",
        "version": "1.0.0",
        "dashboard": "/dashboard",
        "documentation": "/docs",
    }


# ==========================================================
# HEALTH ENDPOINT
# ==========================================================

@app.get("/health")
def health():
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

        return {
            "status": "healthy",
            "database": "connected",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Database connection failed",
        )


# ==========================================================
# SYSTEM STATUS ENDPOINT
# ==========================================================

@app.get("/status")
def system_status():
    scores = get_all_scores()
    processes = get_all_processes()
    events = get_all_events()
    alerts = get_all_alerts()
    incidents = get_all_incidents()

    latest_score = scores[0] if scores else None
    latest_process = processes[0] if processes else None

    with file_monitor_lock:
        monitoring_status = dict(file_monitor_state)

    with detection_monitor_lock:
        detection_status = dict(detection_monitor_state)

    return {
        "system": "RDRS",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat_level": (
            latest_score["threat_level"]
            if latest_score else "Normal"
        ),
        "threat_score": (
            latest_score["score"]
            if latest_score else 0
        ),
        "latest_process": latest_process,
        "file_monitoring": monitoring_status,
        "detection_monitoring": detection_status,
        "database_counts": {
            "events": len(events),
            "processes": len(processes),
            "scores": len(scores),
            "alerts": len(alerts),
            "incidents": len(incidents),
        },
    }


# ==========================================================
# PROCESS MONITORING ENDPOINT
# ==========================================================

@app.get("/processes")
def get_process_monitoring():
    processes = get_all_processes()
    return processes[:30]


# ==========================================================
# ENTROPY SCAN ENDPOINT
# ==========================================================

@app.post("/scan")
def scan_data(request: ScanRequest):
    result = analyze_data(request.data)

    log_event(result)

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "module": "Entropy Analysis",
        "event": "ENTROPY_SCAN",
        "input": request.data,
        "file": None,
        "entropy_score": result["entropy_score"],
        "status": result["status"],
        "alert": result["alert"],
    }

    insert_event(event)

    return result


# ==========================================================
# EVENTS ENDPOINT
# ==========================================================

@app.get("/events")
def get_events():
    return get_all_events()


# ==========================================================
# ALERTS ENDPOINT
# ==========================================================

@app.get("/alerts")
def get_alerts():
    return get_all_alerts()


# ==========================================================
# JSON REPORT ENDPOINT
# ==========================================================

@app.get("/reports")
def get_reports():
    events = get_all_events()
    processes = get_all_processes()
    scores = get_all_scores()
    alerts = get_all_alerts()
    incidents = get_all_incidents()

    return {
        "report_generated": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_events": len(events),
            "total_processes": len(processes),
            "total_scores": len(scores),
            "total_alerts": len(alerts),
            "total_incidents": len(incidents),
        },
        "latest_threat_score": scores[0] if scores else None,
        "recent_events": events[:20],
        "recent_alerts": alerts[:20],
        "recent_incidents": incidents[:20],
    }


# ==========================================================
# INCIDENT REPORT HELPERS
# ==========================================================

def _parse_json_field(value, default):
    """Decode JSON fields stored in SQLite; keep safe defaults on bad data."""

    if value is None or value == "":
        return default

    if isinstance(value, (dict, list)):
        return value

    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return default

    return default


def _parse_timestamp(value):
    """Parse ISO timestamps, including timestamps ending in Z."""

    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed

    except (TypeError, ValueError):
        return None


def _build_incident_report(incident):
    """Build a detailed report without claiming nearby events caused an incident."""

    affected_files = _parse_json_field(
        incident.get("affected_files"),
        [],
    )

    suspect_process = _parse_json_field(
        incident.get("suspect_process"),
        {},
    )

    if not isinstance(affected_files, list):
        affected_files = []

    if not isinstance(suspect_process, dict):
        suspect_process = {
            "recorded_value": suspect_process
        }

    incident_time = _parse_timestamp(
        incident.get("timestamp")
    )

    timeline = []

    if incident_time:
        # Events within five minutes are shown as temporal context only.
        for event in get_all_events():
            event_time = _parse_timestamp(
                event.get("timestamp")
            )

            if (
                event_time
                and abs(
                    (event_time - incident_time).total_seconds()
                ) <= 300
            ):
                timeline.append({
                    "event_id": event.get("id"),
                    "timestamp": event.get("timestamp"),
                    "module": event.get("module"),
                    "event_type": event.get("event_type"),
                    "file_path": event.get("file_path"),
                    "extension": event.get("extension"),
                    "entropy_score": event.get("entropy_score"),
                    "status": event.get("status"),
                    "relationship": "time_window_context_only",
                })

        timeline.sort(
            key=lambda item: item.get("timestamp") or ""
        )

    recommendations = [
        "Keep simulation mode enabled while testing RDRS.",
        "Review the incident timeline and validate whether the recorded activity is expected.",
        "Inspect the quarantine evidence before taking any manual action.",
        "Do not execute suspected files; preserve evidence for analysis.",
    ]

    if not affected_files:
        recommendations.insert(
            1,
            "No affected files were recorded for this incident; verify file-monitor coverage if file activity was expected.",
        )

    return {
        "report_generated": datetime.now(timezone.utc).isoformat(),
        "incident": {
            "id": incident.get("id"),
            "timestamp": incident.get("timestamp"),
            "severity": incident.get("severity"),
            "threat_score": incident.get("score"),
            "summary": incident.get("summary"),
            "status": incident.get("status"),
            "affected_files": affected_files,
            "suspect_process": suspect_process,
            "quarantine_path": incident.get("quarantine_path"),
        },
        "timeline": timeline,
        "timeline_note": (
            "Timeline entries are events recorded within five minutes of the incident timestamp. "
            "They provide time-based context and are not proof of causation."
        ),
        "recommendations": recommendations,
    }


# ==========================================================
# INCIDENT-SPECIFIC JSON REPORT
# ==========================================================

@app.get("/reports/incidents/{incident_id}")
def get_incident_report(incident_id: int):
    incident = next(
        (
            item
            for item in get_all_incidents()
            if str(item.get("id")) == str(incident_id)
        ),
        None,
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return _build_incident_report(incident)


# ==========================================================
# INCIDENT-SPECIFIC CSV REPORT
# ==========================================================

@app.get("/reports/incidents/{incident_id}/csv")
def download_incident_csv_report(incident_id: int):
    incident = next(
        (
            item
            for item in get_all_incidents()
            if str(item.get("id")) == str(incident_id)
        ),
        None,
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    report = _build_incident_report(incident)

    output = io.StringIO()

    fieldnames = [
        "record_type",
        "id",
        "timestamp",
        "severity",
        "score",
        "status",
        "summary",
        "affected_files",
        "suspect_process",
        "quarantine_path",
        "event_id",
        "module",
        "event_type",
        "file_path",
        "extension",
        "entropy_score",
        "relationship",
        "message",
    ]

    writer = csv.DictWriter(
        output,
        fieldnames=fieldnames,
    )

    writer.writeheader()

    details = report["incident"]

    writer.writerow({
        "record_type": "Incident",
        "id": details.get("id"),
        "timestamp": details.get("timestamp"),
        "severity": details.get("severity"),
        "score": details.get("threat_score"),
        "status": details.get("status"),
        "summary": details.get("summary"),
        "affected_files": json.dumps(
            details.get("affected_files", [])
        ),
        "suspect_process": json.dumps(
            details.get("suspect_process", {})
        ),
        "quarantine_path": details.get("quarantine_path"),
    })

    for event in report["timeline"]:
        writer.writerow({
            "record_type": "Timeline Event",
            "id": details.get("id"),
            "timestamp": event.get("timestamp"),
            "event_id": event.get("event_id"),
            "module": event.get("module"),
            "event_type": event.get("event_type"),
            "file_path": event.get("file_path"),
            "extension": event.get("extension"),
            "entropy_score": event.get("entropy_score"),
            "relationship": event.get("relationship"),
        })

    for recommendation in report["recommendations"]:
        writer.writerow({
            "record_type": "Recommendation",
            "id": details.get("id"),
            "message": recommendation,
        })

    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": (
                f'attachment; filename="rdrs_incident_{incident_id}_report.csv"'
            )
        },
    )


# ==========================================================
# CSV REPORT DOWNLOAD ENDPOINT (AGGREGATE)
# ==========================================================

@app.get("/reports/csv")
def download_csv_report():
    output = io.StringIO()

    fieldnames = [
        "record_type",
        "id",
        "timestamp",
        "event_type",
        "file_path",
        "entropy_score",
        "status",
        "severity",
        "score",
        "threat_level",
        "message",
        "summary",
        "affected_files",
        "suspect_process",
        "quarantine_path",
    ]

    writer = csv.DictWriter(
        output,
        fieldnames=fieldnames,
        extrasaction="ignore",
    )

    writer.writeheader()

    for event in get_all_events():
        writer.writerow({
            "record_type": "Event",
            "id": event.get("id"),
            "timestamp": event.get("timestamp"),
            "event_type": event.get("event_type"),
            "file_path": event.get("file_path"),
            "entropy_score": event.get("entropy_score"),
            "status": event.get("status"),
        })

    for score in get_all_scores():
        writer.writerow({
            "record_type": "Threat Score",
            "id": score.get("id"),
            "timestamp": score.get("timestamp"),
            "score": score.get("score"),
            "threat_level": score.get("threat_level"),
            "message": score.get("reasons"),
        })

    for alert in get_all_alerts():
        writer.writerow({
            "record_type": "Alert",
            "id": alert.get("id"),
            "timestamp": alert.get("timestamp"),
            "severity": alert.get("severity"),
            "message": alert.get("message"),
            "status": alert.get("status"),
            "score": alert.get("score"),
        })

    for incident in get_all_incidents():
        writer.writerow({
            "record_type": "Incident",
            "id": incident.get("id"),
            "timestamp": incident.get("timestamp"),
            "severity": incident.get("severity"),
            "score": incident.get("score"),
            "summary": incident.get("summary"),
            "status": incident.get("status"),
            "affected_files": json.dumps(
                _parse_json_field(
                    incident.get("affected_files"),
                    [],
                )
            ),
            "suspect_process": json.dumps(
                _parse_json_field(
                    incident.get("suspect_process"),
                    {},
                )
            ),
            "quarantine_path": incident.get("quarantine_path"),
        })

    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="rdrs_report.csv"'
        },
    )


# ==========================================================
# SETTINGS ENDPOINTS
# ==========================================================

@app.get("/settings")
def get_settings():
    """Read settings from config.yaml for the dashboard."""

    config = load_config()

    return {
        "settings": {
            "simulation": config.get("simulation", {}),
            "process_monitoring": {
                "cpu_spike_threshold": config.get(
                    "process_monitoring", {}
                ).get("cpu_spike_threshold")
            },
        }
    }


@app.post("/settings")
def change_settings(settings: dict):
    """Update approved settings in config.yaml."""

    updated_config = update_config(settings)

    return {
        "message": "Settings updated successfully",
        "settings": updated_config,
    }


# ==========================================================
# FILE MONITOR STATUS
# ==========================================================

@app.get("/monitoring/status")
def get_file_monitoring_status():
    with file_monitor_lock:
        return dict(file_monitor_state)


# ==========================================================
# DETECTION MONITOR STATUS
# ==========================================================

@app.get("/detection/status")
def get_detection_monitoring_status():
    with detection_monitor_lock:
        return dict(detection_monitor_state)


# ==========================================================
# APPLICATION STARTUP INFORMATION
# ==========================================================

if __name__ == "__main__":
    print("RDRS API application")
    print("Database initialization:", initialize_database())
