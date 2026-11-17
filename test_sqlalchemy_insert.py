
from datetime import datetime, timezone

from src.database.db_manager import (
    insert_score,
    get_all_scores,
)

test_score = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "score": 25,
    "threat_level": "Normal",
    "reasons": ["SQLAlchemy integration test"]
}

print(insert_score(test_score))

scores = get_all_scores()

print("\nLatest saved score:")
print(scores[0])

print("\nTotal score records:", len(scores))
