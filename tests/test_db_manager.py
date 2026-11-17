
import importlib
import json

import pytest
from sqlalchemy import create_engine, inspect


@pytest.fixture
def db_manager(tmp_path, monkeypatch):
    """
    Use a temporary SQLite database instead of the real RDRS database.
    """
    import src.database.db_manager as db

    test_db_file = tmp_path / "test_rdrs.db"
    test_engine = create_engine(
        f"sqlite:///{test_db_file.as_posix()}",
        connect_args={"check_same_thread": False},
    )

    monkeypatch.setattr(db, "engine", test_engine)

    yield db

    test_engine.dispose()


@pytest.fixture
def initialized_db(db_manager):
    db_manager.initialize_database()
    return db_manager


def test_initialize_database(initialized_db):
    result = initialized_db.initialize_database()

    assert result == "RDRS database initialized successfully"

    inspector = inspect(initialized_db.engine)

    expected_tables = {
        "events",
        "processes",
        "scores",
        "alerts",
        "incidents",
    }

    assert expected_tables.issubset(set(inspector.get_table_names()))


def test_initialize_database_adds_missing_columns(db_manager):
    with db_manager.engine.begin() as connection:
        connection.execute(
            db_manager.text(
                """
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    module TEXT NOT NULL
                )
                """
            )
        )

        connection.execute(
            db_manager.text(
                """
                CREATE TABLE processes (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL
                )
                """
            )
        )

    db_manager.initialize_database()

    inspector = inspect(db_manager.engine)

    event_columns = {
        column["name"]
        for column in inspector.get_columns("events")
    }

    process_columns = {
        column["name"]
        for column in inspector.get_columns("processes")
    }

    assert "extension" in event_columns
    assert "disk_write_bytes" in process_columns


def test_insert_and_get_event(initialized_db):
    event = {
        "timestamp": "2026-11-13 10:00:00",
        "module": "file_monitor",
        "event": "modified",
        "input": "test data",
        "file": "data/sandbox/test.txt",
        "extension": ".txt",
        "entropy_score": 5.2,
        "status": "normal",
        "alert": False,
    }

    result = initialized_db.insert_event(event)

    assert result == "Event inserted successfully"

    records = initialized_db.get_all_events()

    assert len(records) == 1
    assert records[0]["module"] == "file_monitor"
    assert records[0]["event_type"] == "modified"
    assert records[0]["extension"] == ".txt"
    assert records[0]["alert"] == 0


def test_insert_event_supports_event_type_key(initialized_db):
    event = {
        "timestamp": "2026-11-13 10:00:00",
        "module": "test",
        "event_type": "created",
        "alert": True,
    }

    initialized_db.insert_event(event)

    records = initialized_db.get_all_events()

    assert records[0]["event_type"] == "created"
    assert records[0]["alert"] == 1


def test_insert_and_get_process(initialized_db):
    process = {
        "timestamp": "2026-11-13 10:00:00",
        "pid": 1234,
        "name": "test_process",
        "cpu_percent": 5.5,
        "memory_bytes": 1024,
        "exe": "test.exe",
        "ppid": 100,
        "disk_write_bytes": 200,
    }

    result = initialized_db.insert_process(process)

    assert result == "1 process records inserted successfully"

    records = initialized_db.get_all_processes()

    assert len(records) == 1
    assert records[0]["pid"] == 1234
    assert records[0]["name"] == "test_process"
    assert records[0]["disk_write_bytes"] == 200


def test_insert_multiple_processes(initialized_db):
    processes = [
        {
            "timestamp": "2026-11-13 10:00:00",
            "pid": 100,
            "name": "process_one",
        },
        {
            "timestamp": "2026-11-13 10:00:01",
            "pid": 200,
            "name": "process_two",
        },
    ]

    result = initialized_db.insert_processes(processes)

    assert result == "2 process records inserted successfully"
    assert len(initialized_db.get_all_processes()) == 2


def test_insert_empty_process_list(initialized_db):
    result = initialized_db.insert_processes([])

    assert result == "0 process records inserted successfully"
    assert initialized_db.get_all_processes() == []


def test_insert_and_get_score(initialized_db):
    score = {
        "timestamp": "2026-11-13 10:00:00",
        "score": 85,
        "threat_level": "Critical",
        "reasons": ["high entropy", "mass rename"],
    }

    result = initialized_db.insert_score(score)

    assert result == "Threat score inserted successfully"

    records = initialized_db.get_all_scores()

    assert len(records) == 1
    assert records[0]["score"] == 85
    assert records[0]["threat_level"] == "Critical"
    assert json.loads(records[0]["reasons"]) == score["reasons"]


def test_insert_score_with_string_reasons(initialized_db):
    score = {
        "timestamp": "2026-11-13 10:00:00",
        "score": 20,
        "threat_level": "Normal",
        "reasons": "No suspicious activity",
    }

    initialized_db.insert_score(score)

    records = initialized_db.get_all_scores()

    assert records[0]["reasons"] == "No suspicious activity"


def test_insert_and_get_alert(initialized_db):
    alert = {
        "timestamp": "2026-11-13 10:00:00",
        "severity": "Critical",
        "message": "Suspicious file activity",
        "score": 90,
        "status": "open",
        "event_id": 1,
    }

    result = initialized_db.insert_alert(alert)

    assert result == "Alert inserted successfully"

    records = initialized_db.get_all_alerts()

    assert len(records) == 1
    assert records[0]["severity"] == "Critical"
    assert records[0]["message"] == "Suspicious file activity"


def test_insert_and_get_incident(initialized_db):
    incident = {
        "timestamp": "2026-11-13 10:00:00",
        "severity": "Critical",
        "score": 95,
        "summary": "Simulated ransomware activity",
        "affected_files": ["test1.txt", "test2.txt"],
        "suspect_process": {"name": "test_simulator", "pid": 1234},
        "status": "open",
        "quarantine_path": "data/quarantine/test",
    }

    result = initialized_db.insert_incident(incident)

    assert result == "Incident inserted successfully"

    records = initialized_db.get_all_incidents()

    assert len(records) == 1
    assert records[0]["severity"] == "Critical"
    assert json.loads(records[0]["affected_files"]) == [
        "test1.txt",
        "test2.txt",
    ]
    assert json.loads(records[0]["suspect_process"]) == {
        "name": "test_simulator",
        "pid": 1234,
    }


def test_insert_incident_with_string_values(initialized_db):
    incident = {
        "timestamp": "2026-11-13 10:00:00",
        "affected_files": "file1.txt",
        "suspect_process": "test_process",
    }

    initialized_db.insert_incident(incident)

    records = initialized_db.get_all_incidents()

    assert records[0]["affected_files"] == "file1.txt"
    assert records[0]["suspect_process"] == "test_process"


def test_get_empty_tables(initialized_db):
    assert initialized_db.get_all_events() == []
    assert initialized_db.get_all_processes() == []
    assert initialized_db.get_all_scores() == []
    assert initialized_db.get_all_alerts() == []
    assert initialized_db.get_all_incidents() == []


def test_get_connection(initialized_db):
    connection = initialized_db.get_connection()

    try:
        result = connection.execute(
            initialized_db.text("SELECT 1")
        )

        assert result.scalar() == 1
    finally:
        connection.close()
