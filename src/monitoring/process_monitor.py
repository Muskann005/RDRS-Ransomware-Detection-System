
import time
import psutil
import yaml

from pathlib import Path
from datetime import datetime, timezone

from src.database.db_manager import insert_processes


PROJECT_DIR = Path(__file__).resolve().parents[2]
CONFIG_FILE = PROJECT_DIR / "config.yaml"


def load_config():
    with CONFIG_FILE.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


def collect_processes():
    """Collect snapshots of currently running processes."""

    processes = []

    for process in psutil.process_iter(
        ["pid", "name", "cpu_percent", "memory_info", "exe", "ppid"]
    ):
        try:
            info = process.info
            memory = info.get("memory_info")

            try:
                io_info = process.io_counters()
                disk_write_bytes = (
                    io_info.write_bytes if io_info else 0
                )
            except (
                psutil.AccessDenied,
                psutil.NoSuchProcess,
                psutil.ZombieProcess,
                AttributeError,
                NotImplementedError
            ):
                disk_write_bytes = 0

            process_data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "pid": info.get("pid"),
                "name": info.get("name"),
                "cpu_percent": info.get("cpu_percent") or 0.0,
                "memory_bytes": memory.rss if memory else 0,
                "exe": info.get("exe"),
                "ppid": info.get("ppid"),
                "disk_write_bytes": disk_write_bytes
            }

            processes.append(process_data)

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    return processes


def analyze_processes():
    """Detect CPU spikes and processes outside the trusted list."""

    config = load_config()
    settings = config.get("process_monitoring", {})

    cpu_threshold = float(
        settings.get("cpu_spike_threshold", 80.0)
    )

    trusted_processes = {
        name.lower()
        for name in settings.get("trusted_processes", [])
    }

    sample_interval = float(
        settings.get("process_sample_interval", 1)
    )

    # Measure overall system CPU usage over the configured interval.
    system_cpu_percent = psutil.cpu_percent(
        interval=sample_interval
    )

    processes = collect_processes()

    unknown_processes = []

    for process in processes:
        process_name = process.get("name")

        if process_name and process_name.lower() not in trusted_processes:
            unknown_processes.append(process)

    cpu_spike = system_cpu_percent >= cpu_threshold

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system_cpu_percent": system_cpu_percent,
        "cpu_threshold": cpu_threshold,
        "cpu_spike": cpu_spike,
        "unknown_process": len(unknown_processes) > 0,
        "unknown_processes": unknown_processes,
        "process_count": len(processes),
        "processes": processes
    }


if __name__ == "__main__":

    print("RDRS PROCESS MONITOR")
    print("-------------------")

    result = analyze_processes()

    print("Total processes:", result["process_count"])
    print("System CPU usage:", result["system_cpu_percent"], "%")
    print("CPU spike detected:", result["cpu_spike"])
    print("Unknown processes:", len(result["unknown_processes"]))

    # Save process snapshots to the existing database.
    message = insert_processes(result["processes"])
    print(message)

    print("\nSample process records:")

    for process in result["processes"][:5]:
        print(process)
