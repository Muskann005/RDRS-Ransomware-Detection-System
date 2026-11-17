
import os
from pathlib import Path

from sqlalchemy import create_engine, text
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


# ---------------- CONNECTION TEST ----------------

def test_database_connection():
    try:
        with engine.connect() as connection:
            result = connection.execute(text("SELECT 1"))

            print("SQLAlchemy connection successful!")
            print("Test result:", result.scalar())
            print("Database path:", DB_FILE)

            tables = connection.execute(
                text(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' ORDER BY name"
                )
            )

            print("\nExisting database tables:")

            for table in tables:
                print("-", table[0])

    except Exception as error:
        print("Database connection failed:", error)


if __name__ == "__main__":
    test_database_connection()

