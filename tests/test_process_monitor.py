
from types import SimpleNamespace

import psutil
import pytest

from src.monitoring import process_monitor as pm


@pytest.fixture
def mocked_config(monkeypatch):
    config = {
        "process_monitoring": {
            "cpu_spike_threshold": 80.0,
            "trusted_processes": [
                "python.exe",
                "code.exe",
                "explorer.exe"
            ],
            "process_sample_interval": 0
        }
    }

    monkeypatch.setattr(pm, "load_config", lambda: config)
    return config


def make_process(
    pid=100,
    name="python.exe",
    cpu=5.0,
    memory=1024,
    exe="C:\\Python\\python.exe",
    ppid=1,
    disk_write=2048
):
    info = {
        "pid": pid,
        "name": name,
        "cpu_percent": cpu,
        "memory_info": SimpleNamespace(rss=memory),
        "exe": exe,
        "ppid": ppid
    }

    process = SimpleNamespace(
        info=info,
        io_counters=lambda: SimpleNamespace(
            write_bytes=disk_write
        )
    )

    return process


def test_collect_processes_success(monkeypatch):
    process = make_process()

    monkeypatch.setattr(
        pm.psutil,
        "process_iter",
        lambda attrs: [process]
    )

    result = pm.collect_processes()

    assert len(result) == 1
    assert result[0]["pid"] == 100
    assert result[0]["name"] == "python.exe"
    assert result[0]["memory_bytes"] == 1024
    assert result[0]["disk_write_bytes"] == 2048
    assert result[0]["cpu_percent"] == 5.0
    assert "timestamp" in result[0]


def test_collect_processes_empty(monkeypatch):
    monkeypatch.setattr(
        pm.psutil,
        "process_iter",
        lambda attrs: []
    )

    assert pm.collect_processes() == []


@pytest.mark.parametrize(
    "error",
    [
        psutil.AccessDenied,
        psutil.NoSuchProcess,
        psutil.ZombieProcess
    ]
)
def test_collect_processes_skips_unavailable_process(
    monkeypatch,
    error
):
    process = make_process()

    class UnavailableProcess:
        info = process.info

        def io_counters(self):
            return process.io_counters()

    unavailable = UnavailableProcess()

    def fake_process_iter(attrs):
        raise error(100)

    monkeypatch.setattr(
        pm.psutil,
        "process_iter",
        lambda attrs: [unavailable]
    )

    # Accessing process information can fail for unavailable processes.
    class FailingProcess:
        @property
        def info(self):
            raise error(100)

    monkeypatch.setattr(
        pm.psutil,
        "process_iter",
        lambda attrs: [FailingProcess()]
    )

    assert pm.collect_processes() == []


@pytest.mark.parametrize(
    "error",
    [
        psutil.AccessDenied,
        psutil.NoSuchProcess,
        psutil.ZombieProcess,
        AttributeError,
        NotImplementedError
    ]
)
def test_collect_processes_handles_io_errors(
    monkeypatch,
    error
):
    process = make_process()

    def failing_io():
        raise error("I/O unavailable")

    process.io_counters = failing_io

    monkeypatch.setattr(
        pm.psutil,
        "process_iter",
        lambda attrs: [process]
    )

    result = pm.collect_processes()

    assert len(result) == 1
    assert result[0]["disk_write_bytes"] == 0


def test_collect_processes_handles_missing_memory(monkeypatch):
    process = make_process()
    process.info["memory_info"] = None

    monkeypatch.setattr(
        pm.psutil,
        "process_iter",
        lambda attrs: [process]
    )

    result = pm.collect_processes()

    assert result[0]["memory_bytes"] == 0


def test_collect_processes_handles_zero_cpu(monkeypatch):
    process = make_process(cpu=0)

    monkeypatch.setattr(
        pm.psutil,
        "process_iter",
        lambda attrs: [process]
    )

    result = pm.collect_processes()

    assert result[0]["cpu_percent"] == 0.0


def test_load_config_reads_yaml(monkeypatch, tmp_path):
    config_file = tmp_path / "config.yaml"

    config_file.write_text(
        "process_monitoring:\n"
        "  cpu_spike_threshold: 75\n",
        encoding="utf-8"
    )

    monkeypatch.setattr(pm, "CONFIG_FILE", config_file)

    result = pm.load_config()

    assert result["process_monitoring"]["cpu_spike_threshold"] == 75


def test_analyze_processes_no_spike_and_trusted_process(
    monkeypatch,
    mocked_config
):
    process = make_process(name="python.exe")

    monkeypatch.setattr(
        pm.psutil,
        "cpu_percent",
        lambda interval: 30.0
    )

    monkeypatch.setattr(
        pm,
        "collect_processes",
        lambda: [
            {
                "pid": process.info["pid"],
                "name": process.info["name"]
            }
        ]
    )

    result = pm.analyze_processes()

    assert result["system_cpu_percent"] == 30.0
    assert result["cpu_spike"] is False
    assert result["unknown_process"] is False
    assert result["unknown_processes"] == []
    assert result["process_count"] == 1


def test_analyze_processes_detects_cpu_spike(
    monkeypatch,
    mocked_config
):
    monkeypatch.setattr(
        pm.psutil,
        "cpu_percent",
        lambda interval: 90.0
    )

    monkeypatch.setattr(
        pm,
        "collect_processes",
        lambda: []
    )

    result = pm.analyze_processes()

    assert result["cpu_spike"] is True
    assert result["system_cpu_percent"] == 90.0


def test_analyze_processes_detects_unknown_process(
    monkeypatch,
    mocked_config
):
    unknown = {
        "pid": 200,
        "name": "unknown_test_process.exe"
    }

    monkeypatch.setattr(
        pm.psutil,
        "cpu_percent",
        lambda interval: 20.0
    )

    monkeypatch.setattr(
        pm,
        "collect_processes",
        lambda: [unknown]
    )

    result = pm.analyze_processes()

    assert result["unknown_process"] is True
    assert result["unknown_processes"] == [unknown]


def test_analyze_processes_uses_case_insensitive_trust(
    monkeypatch,
    mocked_config
):
    process = {
        "pid": 101,
        "name": "PYTHON.EXE"
    }

    monkeypatch.setattr(
        pm.psutil,
        "cpu_percent",
        lambda interval: 10.0
    )

    monkeypatch.setattr(
        pm,
        "collect_processes",
        lambda: [process]
    )

    result = pm.analyze_processes()

    assert result["unknown_process"] is False


def test_analyze_processes_handles_missing_process_name(
    monkeypatch,
    mocked_config
):
    process = {
        "pid": 102,
        "name": None
    }

    monkeypatch.setattr(
        pm.psutil,
        "cpu_percent",
        lambda interval: 10.0
    )

    monkeypatch.setattr(
        pm,
        "collect_processes",
        lambda: [process]
    )

    result = pm.analyze_processes()

    assert result["unknown_process"] is False
    assert result["unknown_processes"] == []


def test_cpu_exactly_at_threshold_is_spike(
    monkeypatch,
    mocked_config
):
    monkeypatch.setattr(
        pm.psutil,
        "cpu_percent",
        lambda interval: 80.0
    )

    monkeypatch.setattr(
        pm,
        "collect_processes",
        lambda: []
    )

    result = pm.analyze_processes()

    assert result["cpu_spike"] is True
