
import psutil

print("Checking pet.exe")
print("----------------")

found = False

for process in psutil.process_iter(
    ["pid", "name", "exe", "username", "ppid"]
):
    try:
        if (process.info.get("name") or "").lower() == "pet.exe":
            found = True
            print("PID:", process.info.get("pid"))
            print("Name:", process.info.get("name"))
            print("Executable path:", process.info.get("exe"))
            print("Username:", process.info.get("username"))
            print("Parent PID:", process.info.get("ppid"))

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        continue

if not found:
    print("pet.exe is no longer running.")
