
from pathlib import Path
from loguru import logger

LOG_DIR = Path("logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

logger.remove()

LOG_FILES = {
    "system": "system.log",
    "events": "events.log",
    "alerts": "alerts.log",
    "errors": "errors.log",
    "audit": "audit.log"
}

for log_name, filename in LOG_FILES.items():
    logger.add(
        LOG_DIR / filename,
        rotation="5 MB",
        retention="7 days",
        encoding="utf-8",
        level="DEBUG",
        enqueue=True,
        filter=lambda record, name=log_name:
            record["extra"].get("channel") == name
    )


def get_logger(channel="system"):
    """Return a logger for a specific log category."""

    if channel not in LOG_FILES:
        raise ValueError(f"Unknown log channel: {channel}")

    return logger.bind(channel=channel)
