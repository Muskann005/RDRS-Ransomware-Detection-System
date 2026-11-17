
import pytest

from src.detection import threat_scoring


@pytest.fixture
def no_database_save(monkeypatch):
    """Prevent tests from writing to the real SQLite database."""
    monkeypatch.setattr(
        threat_scoring,
        "insert_score",
        lambda result: "Threat score inserted successfully"
    )


def calculate(result=None, cpu_spike=False, unknown_process=False):
    """Calculate a score without saving it to the database."""
    return threat_scoring.calculate_threat_score(
        detection_result=result or {},
        cpu_spike=cpu_spike,
        unknown_process=unknown_process,
        save_to_database=False
    )


def test_normal_threat_score(no_database_save):
    result = calculate()

    assert result["score"] == 0
    assert result["threat_level"] == "Normal"
    assert result["reasons"] == []


def test_rapid_file_modifications(no_database_save):
    result = calculate({"files_modified": 11})

    assert result["score"] == 40
    assert "Rapid file modifications (+40)" in result["reasons"]


def test_mass_file_renaming(no_database_save):
    result = calculate({"files_renamed": 6})

    assert result["score"] == 30
    assert "Mass file renaming (+30)" in result["reasons"]


def test_high_file_entropy(no_database_save):
    result = calculate({"average_entropy": 7.0})

    assert result["score"] == 25
    assert "High file entropy (+25)" in result["reasons"]


def test_cpu_spike(no_database_save):
    result = calculate(cpu_spike=True)

    assert result["score"] == 15
    assert "CPU spike (+15)" in result["reasons"]


def test_unknown_process(no_database_save):
    result = calculate(unknown_process=True)

    assert result["score"] == 10
    assert "Unknown process (+10)" in result["reasons"]


def test_combined_detection_factors(no_database_save):
    result = calculate(
        {
            "files_modified": 11,
            "files_renamed": 6,
            "average_entropy": 7.0
        },
        cpu_spike=True,
        unknown_process=True
    )

    assert result["score"] == 100
    assert result["threat_level"] == "Critical"
    assert len(result["reasons"]) == 5


def test_score_is_capped_at_100(no_database_save):
    result = calculate(
        {
            "files_modified": 11,
            "files_renamed": 6,
            "average_entropy": 7.0
        },
        cpu_spike=True,
        unknown_process=True
    )

    assert result["score"] <= 100


def test_warning_level(no_database_save):
    # 40 + 10 = 50
    result = calculate(
        {"files_modified": 11},
        unknown_process=True
    )

    assert result["score"] == 50
    assert result["threat_level"] == "Warning"


def test_critical_level(no_database_save):
    # 40 + 30 = 70
    result = calculate(
        {
            "files_modified": 11,
            "files_renamed": 6
        }
    )

    assert result["score"] == 70
    assert result["threat_level"] == "Critical"


def test_modification_threshold_is_strict(no_database_save):
    result = calculate({"files_modified": 10})

    assert result["score"] == 0


def test_rename_threshold_is_strict(no_database_save):
    result = calculate({"files_renamed": 5})

    assert result["score"] == 0


def test_entropy_below_threshold(no_database_save):
    result = calculate({"average_entropy": 6.99})

    assert result["score"] == 0


def test_database_save_disabled(no_database_save, monkeypatch):
    def unexpected_save(result):
        pytest.fail("Database save should not be called")

    monkeypatch.setattr(
        threat_scoring,
        "insert_score",
        unexpected_save
    )

    result = calculate()

    assert "database_status" not in result


def test_database_save_enabled(monkeypatch):
    monkeypatch.setattr(
        threat_scoring,
        "insert_score",
        lambda result: "Threat score inserted successfully"
    )

    result = threat_scoring.calculate_threat_score(
        detection_result={},
        save_to_database=True
    )

    assert result["database_status"] == "Threat score inserted successfully"


def test_result_contains_timestamp(no_database_save):
    result = calculate()

    assert "timestamp" in result
    assert result["timestamp"].endswith("+00:00")
