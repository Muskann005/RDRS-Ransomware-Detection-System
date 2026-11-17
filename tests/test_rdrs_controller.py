
from datetime import datetime, timezone, timedelta

import yaml
import pytest

from src.detection import rdrs_controller as controller


@pytest.fixture
def controller_environment(tmp_path, monkeypatch):
    """Provide isolated configuration and mocked database operations."""

    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        yaml.safe_dump({
            "monitoring": {
                "analysis_window_seconds": 60
            }
        }),
        encoding="utf-8"
    )

    monkeypatch.setattr(controller, "CONFIG_FILE", config_file)

    events = []

    monkeypatch.setattr(
        controller,
        "get_all_events",
        lambda: events
    )

    monkeypatch.setattr(
        controller,
        "_incident_active_for_burst",
        False
    )

    return {
        "config_file": config_file,
        "events": events
    }


# ---------------------------------------------------------
# CONFIGURATION TESTS
# ---------------------------------------------------------

def test_load_config(controller_environment):
    config = controller.load_config()

    assert config["monitoring"]["analysis_window_seconds"] == 60


# ---------------------------------------------------------
# AFFECTED FILE TESTS
# ---------------------------------------------------------

def test_get_affected_files_returns_recent_unique_files(
    controller_environment
):
    now = datetime.now(timezone.utc)

    controller_environment["events"].extend([
        {
            "timestamp": now.isoformat(),
            "file_path": "data/sandbox/a.txt"
        },
        {
            "timestamp": now.isoformat(),
            "file_path": "data/sandbox/a.txt"
        },
        {
            "timestamp": now.isoformat(),
            "file": "data/sandbox/b.txt"
        }
    ])

    result = controller.get_affected_files(60)

    assert result == [
        "data/sandbox/a.txt",
        "data/sandbox/b.txt"
    ]


def test_get_affected_files_ignores_old_events(
    controller_environment
):
    old_time = (
        datetime.now(timezone.utc) - timedelta(minutes=5)
    ).isoformat()

    controller_environment["events"].append({
        "timestamp": old_time,
        "file_path": "old.txt"
    })

    assert controller.get_affected_files(60) == []


def test_get_affected_files_ignores_invalid_timestamps(
    controller_environment
):
    controller_environment["events"].extend([
        {
            "timestamp": "invalid timestamp",
            "file_path": "invalid.txt"
        },
        {
            "timestamp": None,
            "file_path": "missing-time.txt"
        },
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "file_path": "valid.txt"
        }
    ])

    result = controller.get_affected_files(60)

    assert result == ["valid.txt"]


def test_get_affected_files_handles_empty_database(
    controller_environment
):
    assert controller.get_affected_files(60) == []


# ---------------------------------------------------------
# LATEST EVENT ID TESTS
# ---------------------------------------------------------

def test_get_latest_event_id(controller_environment):
    controller_environment["events"].extend([
        {"id": 2},
        {"id": 8},
        {"id": 5}
    ])

    assert controller.get_latest_event_id() == 8


def test_get_latest_event_id_empty(controller_environment):
    assert controller.get_latest_event_id() == 0


def test_get_latest_event_id_ignores_missing_ids(
    controller_environment
):
    controller_environment["events"].extend([
        {"id": None},
        {},
        {"id": 4}
    ])

    assert controller.get_latest_event_id() == 4


def test_get_latest_event_id_with_supplied_events(
    controller_environment
):
    events = [
        {"id": 3},
        {"id": 12},
        {"id": 7}
    ]

    assert controller.get_latest_event_id(events) == 12


# ---------------------------------------------------------
# RUN ONCE TEST
# ---------------------------------------------------------

def test_run_once(
    controller_environment,
    monkeypatch
):
    process_result = {
        "system_cpu_percent": 20.0,
        "cpu_spike": False,
        "unknown_process": False,
        "unknown_processes": [],
        "processes": [
            {"pid": 100, "name": "python.exe"}
        ]
    }

    detection_result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "window_seconds": 60,
        "files_modified": 0,
        "files_renamed": 0,
        "extension_changes": 0,
        "average_entropy": 0.0,
        "suspicious": False,
        "reasons": []
    }

    score_result = {
        "score": 0,
        "threat_level": "Normal",
        "reasons": []
    }

    monkeypatch.setattr(
        controller,
        "analyze_processes",
        lambda: process_result
    )

    monkeypatch.setattr(
        controller,
        "insert_processes",
        lambda processes: "Process snapshots saved"
    )

    monkeypatch.setattr(
        controller,
        "evaluate_detection",
        lambda process: {
            "detection": detection_result,
            "score": score_result
        }
    )

    result = controller.run_once()

    assert result["process"] == process_result
    assert result["detection"] == detection_result
    assert result["score"] == score_result
    assert result["affected_files"] == []


# ---------------------------------------------------------
# DETECTION EVALUATION TESTS
# ---------------------------------------------------------

def test_evaluate_detection_uses_default_process_result(
    controller_environment,
    monkeypatch
):
    detection_result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "window_seconds": 60,
        "files_modified": 0,
        "new_files": 0,
        "files_renamed": 0,
        "extension_changes": 0,
        "average_entropy": 0.0,
        "suspicious": False,
        "reasons": []
    }

    received = {}

    monkeypatch.setattr(
        controller,
        "analyze_file_activity",
        lambda: detection_result
    )

    def fake_score(
        detection,
        cpu_spike=False,
        unknown_process=False,
        save_to_database=True
    ):
        received["cpu_spike"] = cpu_spike
        received["unknown_process"] = unknown_process
        received["save_to_database"] = save_to_database

        return {
            "score": 0,
            "threat_level": "Normal",
            "reasons": []
        }

    monkeypatch.setattr(
        controller,
        "calculate_threat_score",
        fake_score
    )

    result = controller.evaluate_detection()

    assert received["cpu_spike"] is False
    assert received["unknown_process"] is False
    assert received["save_to_database"] is True
    assert result["detection"] == detection_result


def test_critical_incident_failure_does_not_activate_burst(
    controller_environment,
    monkeypatch
):
    detection_result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "window_seconds": 60,
        "files_modified": 11,
        "new_files": 0,
        "files_renamed": 6,
        "extension_changes": 6,
        "average_entropy": 7.5,
        "suspicious": True,
        "reasons": ["Simulated suspicious activity"]
    }

    monkeypatch.setattr(
        controller,
        "analyze_file_activity",
        lambda: detection_result
    )

    monkeypatch.setattr(
        controller,
        "calculate_threat_score",
        lambda *args, **kwargs: {
            "score": 100,
            "threat_level": "Critical",
            "reasons": []
        }
    )

    monkeypatch.setattr(
        controller,
        "handle_incident",
        lambda *args, **kwargs: {
            "incident_created": False
        }
    )

    controller.evaluate_detection()

    assert controller._incident_active_for_burst is False


def test_non_suspicious_non_critical_window_resets_burst(
    controller_environment,
    monkeypatch
):
    monkeypatch.setattr(
        controller,
        "_incident_active_for_burst",
        True
    )

    detection_result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "window_seconds": 60,
        "files_modified": 0,
        "new_files": 0,
        "files_renamed": 0,
        "extension_changes": 0,
        "average_entropy": 0.0,
        "suspicious": False,
        "reasons": []
    }

    monkeypatch.setattr(
        controller,
        "analyze_file_activity",
        lambda: detection_result
    )

    monkeypatch.setattr(
        controller,
        "calculate_threat_score",
        lambda *args, **kwargs: {
            "score": 0,
            "threat_level": "Normal",
            "reasons": []
        }
    )

    controller.evaluate_detection()

    assert controller._incident_active_for_burst is False


# ---------------------------------------------------------
# CONTINUOUS MONITORING TEST HELPERS
# ---------------------------------------------------------

def make_process_result():
    """Create a harmless mocked process-monitoring result."""

    return {
        "system_cpu_percent": 15.0,
        "cpu_spike": False,
        "unknown_process": False,
        "unknown_processes": [],
        "processes": [
            {"pid": 100, "name": "python.exe"}
        ]
    }


# ---------------------------------------------------------
# CONTINUOUS MONITORING TESTS
# ---------------------------------------------------------

def test_run_continuously_detects_new_file_events(
    controller_environment,
    monkeypatch
):
    process_result = make_process_result()
    evaluated_processes = []

    monkeypatch.setattr(
        controller,
        "load_config",
        lambda: {
            "monitoring": {
                "analysis_window_seconds": 60
            }
        }
    )

    monkeypatch.setattr(
        controller,
        "run_once",
        lambda: {"process": process_result}
    )

    monkeypatch.setattr(
        controller,
        "evaluate_detection",
        lambda process: evaluated_processes.append(process)
    )

    def fake_sleep(seconds):
        if not controller_environment["events"]:
            controller_environment["events"].append({
                "id": 1,
                "event_type": "MODIFIED",
                "file_path": "data/sandbox/test.txt"
            })
        else:
            raise KeyboardInterrupt

    monkeypatch.setattr(
        controller.time,
        "sleep",
        fake_sleep
    )

    monkeypatch.setattr(
        controller.time,
        "monotonic",
        lambda: 100
    )

    controller.run_continuously()

    assert evaluated_processes == [process_result]


def test_run_continuously_ignores_unrelated_events(
    controller_environment,
    monkeypatch
):
    process_result = make_process_result()
    evaluated_processes = []

    monkeypatch.setattr(
        controller,
        "load_config",
        lambda: {
            "monitoring": {
                "analysis_window_seconds": 60
            }
        }
    )

    monkeypatch.setattr(
        controller,
        "run_once",
        lambda: {"process": process_result}
    )

    monkeypatch.setattr(
        controller,
        "evaluate_detection",
        lambda process: evaluated_processes.append(process)
    )

    def fake_sleep(seconds):
        if not controller_environment["events"]:
            controller_environment["events"].append({
                "id": 1,
                "event_type": "PROCESS_UPDATE"
            })
        else:
            raise KeyboardInterrupt

    monkeypatch.setattr(
        controller.time,
        "sleep",
        fake_sleep
    )

    monkeypatch.setattr(
        controller.time,
        "monotonic",
        lambda: 100
    )

    controller.run_continuously()

    assert evaluated_processes == []


def test_run_continuously_performs_periodic_process_monitoring(
    controller_environment,
    monkeypatch
):
    initial_process = make_process_result()
    periodic_process = make_process_result()
    periodic_process["system_cpu_percent"] = 45.0

    evaluated_processes = []
    inserted_processes = []

    monkeypatch.setattr(
        controller,
        "load_config",
        lambda: {
            "monitoring": {
                "analysis_window_seconds": 1
            }
        }
    )

    monkeypatch.setattr(
        controller,
        "run_once",
        lambda: {"process": initial_process}
    )

    monkeypatch.setattr(
        controller,
        "analyze_processes",
        lambda: periodic_process
    )

    monkeypatch.setattr(
        controller,
        "insert_processes",
        lambda processes: inserted_processes.append(processes)
    )

    monkeypatch.setattr(
        controller,
        "evaluate_detection",
        lambda process: evaluated_processes.append(process)
    )

    sleep_calls = {"count": 0}

    def fake_sleep(seconds):
        sleep_calls["count"] += 1

        if sleep_calls["count"] > 1:
            raise KeyboardInterrupt

    monkeypatch.setattr(
        controller.time,
        "sleep",
        fake_sleep
    )

    # Supply enough monotonic values for all controller calls.
    monotonic_values = iter([100, 102, 102])

    monkeypatch.setattr(
        controller.time,
        "monotonic",
        lambda: next(monotonic_values, 102)
    )

    controller.run_continuously()

    assert evaluated_processes == [periodic_process]

    assert inserted_processes == [
        periodic_process["processes"]
    ]


@pytest.mark.parametrize(
    "invalid_interval",
    ["invalid", 0, -10, None]
)
def test_run_continuously_uses_default_interval_for_invalid_config(
    controller_environment,
    monkeypatch,
    invalid_interval
):
    initial_process = make_process_result()
    periodic_process = make_process_result()

    analyzed = []

    monkeypatch.setattr(
        controller,
        "load_config",
        lambda: {
            "monitoring": {
                "analysis_window_seconds": invalid_interval
            }
        }
    )

    monkeypatch.setattr(
        controller,
        "run_once",
        lambda: {"process": initial_process}
    )

    def fake_analyze_processes():
        analyzed.append(True)
        return periodic_process

    monkeypatch.setattr(
        controller,
        "analyze_processes",
        fake_analyze_processes
    )

    monkeypatch.setattr(
        controller,
        "insert_processes",
        lambda processes: "Process snapshots saved"
    )

    monkeypatch.setattr(
        controller,
        "evaluate_detection",
        lambda process: None
    )

    sleep_calls = {"count": 0}

    def fake_sleep(seconds):
        sleep_calls["count"] += 1

        if sleep_calls["count"] > 1:
            raise KeyboardInterrupt

    monkeypatch.setattr(
        controller.time,
        "sleep",
        fake_sleep
    )

    # The controller calls monotonic more than once.
    monotonic_values = iter([100, 160, 160])

    monkeypatch.setattr(
        controller.time,
        "monotonic",
        lambda: next(monotonic_values, 160)
    )

    controller.run_continuously()

    # Invalid configuration should use the 60-second default.
    assert analyzed == [True]


def test_run_continuously_stops_safely_on_keyboard_interrupt(
    controller_environment,
    monkeypatch
):
    process_result = make_process_result()

    monkeypatch.setattr(
        controller,
        "load_config",
        lambda: {
            "monitoring": {
                "analysis_window_seconds": 60
            }
        }
    )

    monkeypatch.setattr(
        controller,
        "run_once",
        lambda: {"process": process_result}
    )

    monkeypatch.setattr(
        controller.time,
        "monotonic",
        lambda: 100
    )

    def interrupt_sleep(seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(
        controller.time,
        "sleep",
        interrupt_sleep
    )

    # KeyboardInterrupt should be handled safely.
    controller.run_continuously()
