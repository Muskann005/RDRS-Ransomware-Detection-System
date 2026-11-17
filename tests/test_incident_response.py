
import yaml
import pytest

from pathlib import Path

from src.response import incident_response as ir


@pytest.fixture
def response_environment(tmp_path, monkeypatch):
    """Create isolated directories for safe incident response tests."""

    sandbox = tmp_path / "sandbox"
    quarantine = tmp_path / "quarantine"

    sandbox.mkdir()
    quarantine.mkdir()

    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        yaml.safe_dump({
            "simulation": {"enabled": True}
        }),
        encoding="utf-8"
    )

    monkeypatch.setattr(ir, "SANDBOX_DIR", sandbox)
    monkeypatch.setattr(ir, "QUARANTINE_DIR", quarantine)
    monkeypatch.setattr(ir, "CONFIG_FILE", config_file)

    return {
        "sandbox": sandbox,
        "quarantine": quarantine,
        "config_file": config_file,
    }


def test_load_config(response_environment):
    config = ir.load_config()

    assert config["simulation"]["enabled"] is True


def test_copy_evidence_success(response_environment):
    sandbox = response_environment["sandbox"]

    original = sandbox / "test.txt"
    original.write_text("Safe test evidence", encoding="utf-8")

    result = ir.copy_evidence_to_quarantine([original])

    assert len(result["copied_files"]) == 1
    assert result["skipped_files"] == []

    copied_path = Path(
        result["copied_files"][0]["quarantine"]
    )

    assert copied_path.exists()
    assert copied_path.read_text(encoding="utf-8") == (
        "Safe test evidence"
    )

    # Original evidence must remain untouched.
    assert original.exists()
    assert original.read_text(encoding="utf-8") == (
        "Safe test evidence"
    )


def test_copy_evidence_rejects_outside_file(response_environment):
    outside_file = (
        response_environment["sandbox"].parent / "outside.txt"
    )
    outside_file.write_text("Outside sandbox", encoding="utf-8")

    result = ir.copy_evidence_to_quarantine([outside_file])

    assert result["copied_files"] == []
    assert len(result["skipped_files"]) == 1
    assert (
        result["skipped_files"][0]["reason"]
        == "File is outside the RDRS sandbox"
    )


def test_copy_evidence_missing_file(response_environment):
    missing_file = (
        response_environment["sandbox"] / "missing.txt"
    )

    result = ir.copy_evidence_to_quarantine([missing_file])

    assert result["copied_files"] == []
    assert len(result["skipped_files"]) == 1
    assert result["skipped_files"][0]["reason"] == (
        "File does not exist"
    )


def test_copy_evidence_empty_list(response_environment):
    result = ir.copy_evidence_to_quarantine([])

    assert result["copied_files"] == []
    assert result["skipped_files"] == []
    assert Path(result["quarantine_folder"]).exists()


def test_copy_evidence_avoids_overwriting(response_environment):
    sandbox = response_environment["sandbox"]

    first_dir = sandbox / "first"
    second_dir = sandbox / "second"

    first_dir.mkdir()
    second_dir.mkdir()

    first_file = first_dir / "sample.txt"
    second_file = second_dir / "sample.txt"

    first_file.write_text("First evidence", encoding="utf-8")
    second_file.write_text("Second evidence", encoding="utf-8")

    result = ir.copy_evidence_to_quarantine([
        first_file,
        second_file,
    ])

    assert len(result["copied_files"]) == 2

    copied_paths = [
        Path(item["quarantine"])
        for item in result["copied_files"]
    ]

    assert copied_paths[0] != copied_paths[1]
    assert copied_paths[0].read_text(encoding="utf-8") == (
        "First evidence"
    )
    assert copied_paths[1].read_text(encoding="utf-8") == (
        "Second evidence"
    )


def test_copy_evidence_handles_copy_error(
    response_environment,
    monkeypatch
):
    sandbox = response_environment["sandbox"]

    original = sandbox / "copy_error.txt"
    original.write_text("Safe test data", encoding="utf-8")

    def failing_copy(source, destination):
        raise OSError("Simulated copy failure")

    monkeypatch.setattr(ir.shutil, "copy2", failing_copy)

    result = ir.copy_evidence_to_quarantine([original])

    assert result["copied_files"] == []
    assert len(result["skipped_files"]) == 1
    assert "Simulated copy failure" in (
        result["skipped_files"][0]["reason"]
    )

    # The original must still exist.
    assert original.exists()


def test_handle_non_critical_threat(
    response_environment,
    monkeypatch
):
    monkeypatch.setattr(
        ir,
        "insert_incident",
        lambda incident: pytest.fail(
            "No incident should be inserted"
        )
    )

    monkeypatch.setattr(
        ir,
        "insert_alert",
        lambda alert: pytest.fail(
            "No alert should be inserted"
        )
    )

    result = ir.handle_incident(
        detection_result={},
        score_result={
            "score": 20,
            "threat_level": "Normal",
        },
    )

    assert result["incident_created"] is False
    assert result["message"] == (
        "Threat level is not Critical"
    )


def test_handle_critical_incident_in_simulation_mode(
    response_environment,
    monkeypatch
):
    inserted_incidents = []
    inserted_alerts = []

    def fake_copy(files):
        return {
            "quarantine_folder": "temporary/quarantine",
            "copied_files": [],
            "skipped_files": [],
        }

    monkeypatch.setattr(ir, "copy_evidence_to_quarantine", fake_copy)

    monkeypatch.setattr(
        ir,
        "insert_incident",
        lambda incident: (
            inserted_incidents.append(incident)
            or "Incident inserted successfully"
        )
    )

    monkeypatch.setattr(
        ir,
        "insert_alert",
        lambda alert: (
            inserted_alerts.append(alert)
            or "Alert inserted successfully"
        )
    )

    result = ir.handle_incident(
        detection_result={"suspicious": True},
        score_result={
            "score": 95,
            "threat_level": "Critical",
        },
        affected_files=["test.txt"],
        suspect_process={"name": "safe_test_process"},
    )

    assert result["incident_created"] is True
    assert result["threat_score"] == 95
    assert result["threat_level"] == "Critical"

    assert len(inserted_incidents) == 1
    assert len(inserted_alerts) == 1

    assert inserted_incidents[0]["severity"] == "Critical"
    assert inserted_incidents[0]["affected_files"] == [
        "test.txt"
    ]

    assert inserted_alerts[0]["severity"] == "Critical"
    assert "Score: 95" in inserted_alerts[0]["message"]

    assert "Simulation mode enabled" in (
        result["response_action"]
    )
    assert "Process termination was not performed" in (
        result["response_action"]
    )


def test_handle_critical_incident_simulation_disabled(
    response_environment,
    monkeypatch
):
    config_file = response_environment["config_file"]

    config_file.write_text(
        yaml.safe_dump({
            "simulation": {"enabled": False}
        }),
        encoding="utf-8"
    )

    monkeypatch.setattr(
        ir,
        "copy_evidence_to_quarantine",
        lambda files: {
            "quarantine_folder": "temporary/quarantine",
            "copied_files": [],
            "skipped_files": [],
        }
    )

    monkeypatch.setattr(
        ir,
        "insert_incident",
        lambda incident: "Incident inserted successfully"
    )

    monkeypatch.setattr(
        ir,
        "insert_alert",
        lambda alert: "Alert inserted successfully"
    )

    result = ir.handle_incident(
        detection_result={},
        score_result={
            "score": 90,
            "threat_level": "Critical",
        },
    )

    assert result["incident_created"] is True
    assert "Automatic process termination is disabled" in (
        result["response_action"]
    )


def test_handle_incident_uses_default_values(
    response_environment,
    monkeypatch
):
    inserted_incidents = []

    monkeypatch.setattr(
        ir,
        "copy_evidence_to_quarantine",
        lambda files: {
            "quarantine_folder": "temporary/quarantine",
            "copied_files": [],
            "skipped_files": [],
        }
    )

    monkeypatch.setattr(
        ir,
        "insert_incident",
        lambda incident: (
            inserted_incidents.append(incident)
            or "Incident inserted successfully"
        )
    )

    monkeypatch.setattr(
        ir,
        "insert_alert",
        lambda alert: "Alert inserted successfully"
    )

    result = ir.handle_incident(
        detection_result=None,
        score_result={
            "threat_level": "Critical",
        },
    )

    assert result["incident_created"] is True
    assert result["threat_score"] == 0
    assert inserted_incidents[0]["affected_files"] == []
    assert inserted_incidents[0]["suspect_process"] == {}


def test_handle_incident_records_copied_evidence(
    response_environment,
    monkeypatch
):
    inserted_alerts = []

    monkeypatch.setattr(
        ir,
        "copy_evidence_to_quarantine",
        lambda files: {
            "quarantine_folder": "temporary/quarantine",
            "copied_files": [
                {"original": "a.txt", "quarantine": "q/a.txt"},
                {"original": "b.txt", "quarantine": "q/b.txt"},
            ],
            "skipped_files": [
                {"file": "outside.txt", "reason": "Outside sandbox"}
            ],
        }
    )

    monkeypatch.setattr(
        ir,
        "insert_incident",
        lambda incident: "Incident inserted successfully"
    )

    monkeypatch.setattr(
        ir,
        "insert_alert",
        lambda alert: (
            inserted_alerts.append(alert)
            or "Alert inserted successfully"
        )
    )

    result = ir.handle_incident(
        detection_result={},
        score_result={
            "score": 95,
            "threat_level": "Critical",
        },
    )

    assert result["incident_created"] is True
    assert len(result["quarantine"]["copied_files"]) == 2
    assert len(result["quarantine"]["skipped_files"]) == 1
    assert "Evidence copied: 2" in inserted_alerts[0]["message"]
