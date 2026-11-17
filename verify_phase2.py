
import json
import sqlite3
from pathlib import Path

db_path = Path("reports/rdrs.db")
json_path = Path("logs/events.json")

print("\n========== SQLITE VERIFICATION ==========")

connection = sqlite3.connect(db_path)
connection.row_factory = sqlite3.Row

rows = connection.execute("""
    SELECT timestamp, event_type, file_path, entropy_score, status
    FROM events
    WHERE file_path LIKE '%phase2_%'
    ORDER BY id DESC
""").fetchall()

print("SQLite records:", len(rows))

for row in rows:
    print(dict(row))

connection.close()

print("\n========== JSON VERIFICATION ==========")

if json_path.exists():
    with json_path.open("r", encoding="utf-8") as file:
        events = json.load(file)

    matches = [
        event for event in events
        if "phase2_" in str(event.get("file", ""))
    ]

    print("JSON records:", len(matches))

    for event in matches:
        print(event)

else:
    print("JSON event log not found.")
