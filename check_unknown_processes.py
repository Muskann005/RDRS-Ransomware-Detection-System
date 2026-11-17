
from src.monitoring.process_monitor import analyze_processes

result = analyze_processes()

print("\nRDRS UNKNOWN PROCESS REPORT")
print("===========================")

for process in result["unknown_processes"]:
    print("\nPID:", process.get("pid"))
    print("Name:", process.get("name"))
    print("Executable:", process.get("exe"))
    print("Parent PID:", process.get("ppid"))

print("\nTotal unknown processes:",
      len(result["unknown_processes"]))

print("System CPU:",
      result["system_cpu_percent"], "%")
