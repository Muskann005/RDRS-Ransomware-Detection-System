
from datetime import datetime, timezone

from src.detection.detection_engine import analyze_file_activity

now = datetime.now(timezone.utc)

test_events = []

# Simulate 12 modified files with high entropy
for i in range(12):
    test_events.append({
        "timestamp": now.isoformat(),
        "event_type": "MODIFIED",
        "file_path": f"data/sandbox/high_entropy_{i}.txt",
        "entropy_score": 7.8
    })

result = analyze_file_activity(
    events=test_events,
    now=now
)

print("\nRDRS HIGH ENTROPY TEST")
print("---------------------")

for key, value in result.items():
    print(f"{key}: {value}")

print("\nHigh entropy test completed.")
