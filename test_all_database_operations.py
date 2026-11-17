
from datetime import datetime, timezone

from src.database.db_manager import (
    insert_event,
    insert_process,
    insert_alert,
    insert_incident,
    get_all_events,
    get_all_processes,
    get_all_alerts,
    get_all_incidents,
)

timestamp = datetime.now(timezone.utc).isoformat()

print("TESTING RDRS DATABASE OPERATIONS")
print("--------------------------------")

# 1. Test event insertion
print("\n1. Event:")
print(insert_event({
    "timestamp": timestamp,
    "module": "Database Test",
    "event": "TEST_EVENT",
    "input": "SQLAlchemy integration test",
    "file": "test_file.txt",
    "extension": ".txt",
    "entropy_score": 2.5,
    "status": "normal",
    "alert": False
}))
print("Total events:", len(get_all_events()))

# 2. Test process insertion
print("\n2. Process:")
print(insert_process({
    "timestamp": timestamp,
    "pid": 99999,
    "name": "RDRS_TEST_PROCESS",
    "cpu_percent": 1.0,
    "memory_bytes": 1024,
    "exe": "test_process.exe",
    "ppid": 1,
    "disk_write_bytes": 100
}))
print("Total processes:", len(get_all_processes()))

# 3. Test alert insertion
print("\n3. Alert:")
print(insert_alert({
    "timestamp": timestamp,
    "severity": "Warning",
    "message": "SQLAlchemy integration test alert",
    "score": 25,
    "status": "open"
}))
print("Total alerts:", len(get_all_alerts()))

# 4. Test incident insertion
print("\n4. Incident:")
print(insert_incident({
    "timestamp": timestamp,
    "severity": "Critical",
    "score": 75,
    "summary": "SQLAlchemy integration test incident",
    "affected_files": ["test_file.txt"],
    "suspect_process": {"name": "RDRS_TEST_PROCESS"},
    "status": "open",
    "quarantine_path": "test_quarantine"
}))
print("Total incidents:", len(get_all_incidents()))

print("\nAll database operation tests completed!")
