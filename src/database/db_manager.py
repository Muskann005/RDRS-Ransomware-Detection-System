
import json
import os
from pathlib import Path

from sqlalchemy import (
    create_engine,
    MetaData,
    Table,
    Column,
    Integer,
    Float,
    Text,
    inspect,
    insert,
    select,
    text,
)
from sqlalchemy.orm import sessionmaker


# ---------------- DATABASE CONFIGURATION ----------------

PROJECT_DIR = Path(__file__).resolve().parents[2]

DEFAULT_DB = (
    PROJECT_DIR
    / "reports"
    / "rdrs_recovery_working_20261116.db"
)

DB_FILE = Path(
    os.getenv("RDRS_DB_PATH", str(DEFAULT_DB))
).expanduser()

if not DB_FILE.is_absolute():
    DB_FILE = PROJECT_DIR / DB_FILE

DB_FILE.parent.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite:///{DB_FILE.as_posix()}"


# ---------------- DATABASE ENGINE ----------------

engine = create_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False,
        "timeout": 30,
    },
    echo=False,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)

metadata = MetaData()


# ---------------- TABLE DEFINITIONS ----------------

events = Table(
    "events",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("timestamp", Text, nullable=False),
    Column("module", Text, nullable=False),
    Column("event_type", Text),
    Column("input_data", Text),
    Column("file_path", Text),
    Column("extension", Text),
    Column("entropy_score", Float),
    Column("status", Text),
    Column("alert", Integer, nullable=False, default=0),
)

processes = Table(
    "processes",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("timestamp", Text, nullable=False),
    Column("pid", Integer),
    Column("name", Text),
    Column("cpu_percent", Float),
    Column("memory_bytes", Integer),
    Column("exe", Text),
    Column("ppid", Integer),
    Column("disk_write_bytes", Integer, default=0),
)

scores = Table(
    "scores",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("timestamp", Text, nullable=False),
    Column("score", Float, nullable=False),
    Column("threat_level", Text, nullable=False),
    Column("reasons", Text),
)

alerts = Table(
    "alerts",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("timestamp", Text, nullable=False),
    Column("severity", Text, nullable=False),
    Column("message", Text, nullable=False),
    Column("score", Float),
    Column("status", Text, default="open"),
    Column("event_id", Integer),
)

incidents = Table(
    "incidents",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("timestamp", Text, nullable=False),
    Column("severity", Text, nullable=False),
    Column("score", Float),
    Column("summary", Text),
    Column("affected_files", Text),
    Column("suspect_process", Text),
    Column("status", Text, default="open"),
    Column("quarantine_path", Text),
)


# ---------------- DATABASE INITIALIZATION ----------------

def get_connection():
    return engine.connect()


def initialize_database():
    metadata.create_all(engine)

    inspector = inspect(engine)

    existing_event_columns = {
        column["name"]
        for column in inspector.get_columns("events")
    }

    existing_process_columns = {
        column["name"]
        for column in inspector.get_columns("processes")
    }

    with engine.begin() as connection:

        if "extension" not in existing_event_columns:
            connection.execute(
                text(
                    "ALTER TABLE events "
                    "ADD COLUMN extension TEXT"
                )
            )

        if "disk_write_bytes" not in existing_process_columns:
            connection.execute(
                text(
                    "ALTER TABLE processes "
                    "ADD COLUMN disk_write_bytes INTEGER DEFAULT 0"
                )
            )

    return "RDRS database initialized successfully"


# ---------------- EVENTS ----------------

def insert_event(event):

    values = {
        "timestamp": event.get("timestamp"),
        "module": event.get("module"),
        "event_type": (
            event.get("event")
            or event.get("event_type")
        ),
        "input_data": event.get("input"),
        "file_path": event.get("file"),
        "extension": event.get("extension"),
        "entropy_score": event.get("entropy_score"),
        "status": event.get("status"),
        "alert": int(bool(event.get("alert", False))),
    }

    with engine.begin() as connection:
        connection.execute(
            insert(events).values(**values)
        )

    return "Event inserted successfully"


def get_all_events():

    with engine.connect() as connection:
        result = connection.execute(
            select(events).order_by(events.c.id.desc())
        )

        return [
            dict(row)
            for row in result.mappings()
        ]


# ---------------- PROCESSES ----------------

def insert_process(process):
    return insert_processes([process])


def insert_processes(process_list):

    if not process_list:
        return "0 process records inserted successfully"

    values = [
        {
            "timestamp": process.get("timestamp"),
            "pid": process.get("pid"),
            "name": process.get("name"),
            "cpu_percent": process.get("cpu_percent"),
            "memory_bytes": process.get("memory_bytes"),
            "exe": process.get("exe"),
            "ppid": process.get("ppid"),
            "disk_write_bytes": process.get(
                "disk_write_bytes", 0
            ),
        }
        for process in process_list
    ]

    with engine.begin() as connection:
        connection.execute(
            insert(processes),
            values
        )

    return (
        f"{len(process_list)} process records "
        "inserted successfully"
    )


def get_all_processes():

    with engine.connect() as connection:
        result = connection.execute(
            select(processes).order_by(processes.c.id.desc())
        )

        return [
            dict(row)
            for row in result.mappings()
        ]


# ---------------- THREAT SCORES ----------------

def insert_score(score):

    reasons = score.get("reasons", [])

    if not isinstance(reasons, str):
        reasons = json.dumps(reasons)

    values = {
        "timestamp": score.get("timestamp"),
        "score": score.get("score", 0),
        "threat_level": score.get(
            "threat_level", "Normal"
        ),
        "reasons": reasons,
    }

    with engine.begin() as connection:
        connection.execute(
            insert(scores).values(**values)
        )

    return "Threat score inserted successfully"


def get_all_scores():

    with engine.connect() as connection:
        result = connection.execute(
            select(scores).order_by(scores.c.id.desc())
        )

        return [
            dict(row)
            for row in result.mappings()
        ]


# ---------------- ALERTS ----------------

def insert_alert(alert):

    values = {
        "timestamp": alert.get("timestamp"),
        "severity": alert.get("severity", "Warning"),
        "message": alert.get("message", ""),
        "score": alert.get("score"),
        "status": alert.get("status", "open"),
        "event_id": alert.get("event_id"),
    }

    with engine.begin() as connection:
        connection.execute(
            insert(alerts).values(**values)
        )

    return "Alert inserted successfully"


def get_all_alerts():

    with engine.connect() as connection:
        result = connection.execute(
            select(alerts).order_by(alerts.c.id.desc())
        )

        return [
            dict(row)
            for row in result.mappings()
        ]


# ---------------- INCIDENTS ----------------

def insert_incident(incident):

    affected_files = incident.get(
        "affected_files", []
    )

    suspect_process = incident.get(
        "suspect_process", {}
    )

    if not isinstance(affected_files, str):
        affected_files = json.dumps(affected_files)

    if not isinstance(suspect_process, str):
        suspect_process = json.dumps(suspect_process)

    values = {
        "timestamp": incident.get("timestamp"),
        "severity": incident.get("severity", "Critical"),
        "score": incident.get("score"),
        "summary": incident.get("summary", ""),
        "affected_files": affected_files,
        "suspect_process": suspect_process,
        "status": incident.get("status", "open"),
        "quarantine_path": incident.get("quarantine_path"),
    }

    with engine.begin() as connection:
        connection.execute(
            insert(incidents).values(**values)
        )

    return "Incident inserted successfully"


def get_all_incidents():

    with engine.connect() as connection:
        result = connection.execute(
            select(incidents).order_by(incidents.c.id.desc())
        )

        return [
            dict(row)
            for row in result.mappings()
        ]


# ---------------- MAIN ----------------

if __name__ == "__main__":
    print("Database path:", DB_FILE)
    print(initialize_database())
