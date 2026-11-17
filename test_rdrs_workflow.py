
from datetime import datetime, timezone

from src.detection.detection_engine import analyze_file_activity
from src.detection.threat_scoring import calculate_threat_score
from src.response.incident_response import handle_incident


now = datetime.now(timezone.utc)
timestamp = now.isoformat()

# Safe simulated events - no real files are changed
test_events = []

# Simulate 12 modified files
for i in range(12):
    test_events.append({
        "timestamp": timestamp,
        "event_type": "MODIFIED",
        "file_path": f"data/sandbox/test_{i}.txt",
        "entropy_score": 7.8
    })

# Simulate 6 renames
for i in range(6):
    test_events.append({
        "timestamp": timestamp,
        "event_type": "RENAMED",
        "input_data": f"data/sandbox/document_{i}.docx",
        "file_path": f"data/sandbox/document_{i}.locked",
        "entropy_score": 7.8
    })

print("\nRDRS END-TO-END WORKFLOW TEST")
print("============================")

# 1. Detection
print("\n[1] Detection")

detection = analyze_file_activity(
    events=test_events,
    now=now
)

print(detection)

# 2. Threat scoring
print("\n[2] Threat scoring")

score = calculate_threat_score(
    detection,
    save_to_database=True
)

print(score)

# 3. Incident response
print("\n[3] Incident response")

response = handle_incident(
    detection_result=detection,
    score_result=score,
    affected_files=[],
    suspect_process={"name": "RDRS_SIMULATED_TEST"}
)

print(response)

print("\nEND-TO-END TEST COMPLETED")
