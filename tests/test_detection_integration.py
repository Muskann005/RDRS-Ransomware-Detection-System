
from datetime import datetime, timezone, timedelta

import pytest

from src.detection import rdrs_controller as controller


@pytest.fixture
def isolated_controller(monkeypatch):
    """Isolate controller tests from the real database and response system."""

    config = {
        "monitoring": {
            "analysis_window_seconds": 60
        },
        "detection": {
            "max_modified_files": 10,
            "max_renamed_files": 5,
            "max_extension_changes": 3,
            "high_entropy_threshold": 7.0
        },
        "threat_scoring": {
            "rapid_encryption": 40,
            "mass_rename": 30,
            "high_entropy": 25,
            "cpu_spike": 15,
            "unknown_process": 10
        },
        "simulation": {
            "enabled": True
        }
    }

    monkeypatch.setattr(controller, "load_config", lambda: config)

    # Reset the burst state before and after each test.
    monkeypatch.setattr(
        controller,
        "_incident_active_for_burst",
        False
    )

    events = []

    now = datetime.now(timezone.utc)

    # Simulate 11 different modified files.
    for index in range(11):
        events.append({
            "timestamp": now.isoformat(),
            "event_type": "MODIFIED",
            "file_path": f"test_file_{index}.txt",
            "entropy_score": 7.5
        })

    # Simulate 6 file renames with extension changes.
    for index in range(6):
        events.append({
            "timestamp": now.isoformat(),
            "event_type": "RENAMED",
            "input_data": f"old_file_{index}.txt",
            "file_path": f"new_file_{index}.locked"
        })

    monkeypatch.setattr(
        controller,
        "get_all_events",
        lambda: events
    )

    # The scoring function is tested separately.
    # Here we verify the complete controller flow.
    saved_scores = []

    def fake_calculate_score(
        detection_result,
        cpu_spike=False,
        unknown_process=False,
        save_to_database=True
    ):
        result = {
            "timestamp": now.isoformat(),
            "score": 100,
            "threat_level": "Critical",
            "reasons": [
                "Rapid file modifications (+40)",
                "Mass file renaming (+30)",
                "High file entropy (+25)"
            ]
        }

        saved_scores.append(result)
        return result

    monkeypatch.setattr(
        controller,
        "calculate_threat_score",
        fake_calculate_score
    )

    incidents = []

    def fake_handle_incident(
        detection_result,
        score_result,
        affected_files=None,
        suspect_process=None
    ):
        incidents.append({
            "detection": detection_result,
            "score": score_result,
            "affected_files": affected_files,
            "suspect_process": suspect_process
        })

        return {
            "incident_created": True,
            "message": "Simulated incident created"
        }

    monkeypatch.setattr(
        controller,
        "handle_incident",
        fake_handle_incident
    )

    # Use deterministic timestamps for detection analysis.
    monkeypatch.setattr(
        controller,
        "analyze_file_activity",
        lambda: {
            "timestamp": now.isoformat(),
            "window_seconds": 60,
            "files_modified": 11,
            "new_files": 0,
            "files_renamed": 6,
            "extension_changes": 6,
            "average_entropy": 7.5,
            "high_entropy_threshold": 7.0,
            "suspicious": True,
            "reasons": [
                "Rapid file modifications detected",
                "Mass file renaming detected",
                "Multiple file extension changes detected",
                "High average file entropy detected"
            ]
        }
    )

    return {
        "events": events,
        "incidents": incidents,
        "scores": saved_scores,
        "now": now
    }


def test_event_burst_creates_critical_incident(isolated_controller):
    result = controller.evaluate_detection()

    assert result["detection"]["files_modified"] == 11
    assert result["detection"]["files_renamed"] == 6
    assert result["detection"]["average_entropy"] == 7.5

    assert result["score"]["score"] == 100
    assert result["score"]["threat_level"] == "Critical"

    assert len(isolated_controller["incidents"]) == 1
    assert controller._incident_active_for_burst is True


def test_continuing_burst_does_not_create_duplicate_incident(
    isolated_controller
):
    controller.evaluate_detection()
    controller.evaluate_detection()

    assert len(isolated_controller["incidents"]) == 1


def test_clean_window_resets_incident_burst_state(
    isolated_controller,
    monkeypatch
):
    controller.evaluate_detection()

    assert controller._incident_active_for_burst is True

    monkeypatch.setattr(
        controller,
        "analyze_file_activity",
        lambda: {
            "timestamp": isolated_controller["now"].isoformat(),
            "window_seconds": 60,
            "files_modified": 0,
            "new_files": 0,
            "files_renamed": 0,
            "extension_changes": 0,
            "average_entropy": 0.0,
            "high_entropy_threshold": 7.0,
            "suspicious": False,
            "reasons": []
        }
    )

    monkeypatch.setattr(
        controller,
        "calculate_threat_score",
        lambda *args, **kwargs: {
            "timestamp": isolated_controller["now"].isoformat(),
            "score": 0,
            "threat_level": "Normal",
            "reasons": []
        }
    )

    controller.evaluate_detection()

    assert controller._incident_active_for_burst is False
