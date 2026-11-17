
from src.database import database_connection as db


class FakeResult:
    def scalar(self):
        return 1

    def __iter__(self):
        return iter([
            ("alerts",),
            ("events",),
            ("incidents",),
        ])


class FakeConnection:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, query):
        return FakeResult()


class FakeEngine:
    def connect(self):
        return FakeConnection()


class FailingEngine:
    def connect(self):
        raise RuntimeError("Test database connection failure")


def test_database_path_configuration():
    assert db.DB_FILE.name == "rdrs.db"
    assert db.DB_FILE.parent.name == "reports"
    assert db.DATABASE_URL.startswith("sqlite:///")


def test_engine_configuration():
    assert db.engine is not None
    assert db.engine.echo is False


def test_session_factory_configuration():
    session = db.SessionLocal()

    try:
        assert session is not None
        assert db.SessionLocal.kw["autoflush"] is False
        assert db.SessionLocal.kw["autocommit"] is False
    finally:
        session.close()


def test_database_connection_success(monkeypatch, capsys):
    monkeypatch.setattr(db, "engine", FakeEngine())

    db.test_database_connection()

    output = capsys.readouterr().out

    assert "SQLAlchemy connection successful!" in output
    assert "Test result: 1" in output
    assert "Existing database tables:" in output
    assert "- alerts" in output
    assert "- events" in output
    assert "- incidents" in output


def test_database_connection_failure(monkeypatch, capsys):
    monkeypatch.setattr(db, "engine", FailingEngine())

    db.test_database_connection()

    output = capsys.readouterr().out

    assert "Database connection failed:" in output
    assert "Test database connection failure" in output
