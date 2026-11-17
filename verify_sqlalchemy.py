
from src.database.db_manager import (
    get_all_events,
    get_all_processes,
    get_all_scores,
    get_all_alerts,
    get_all_incidents,
)

print("RDRS DATABASE VERIFICATION")
print("--------------------------")

print("Events:", len(get_all_events()))
print("Processes:", len(get_all_processes()))
print("Scores:", len(get_all_scores()))
print("Alerts:", len(get_all_alerts()))
print("Incidents:", len(get_all_incidents()))

print("\nSQLAlchemy verification completed!")
