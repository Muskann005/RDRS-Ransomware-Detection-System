
import sqlite3

connection = sqlite3.connect("reports/rdrs.db")
connection.row_factory = sqlite3.Row

cursor = connection.cursor()

cursor.execute("""
    SELECT pid, name, cpu_percent, memory_bytes,
           disk_write_bytes, exe
    FROM processes
    ORDER BY id DESC
    LIMIT 5
""")

rows = cursor.fetchall()

print("Latest 5 saved process records:\n")

for row in rows:
    print(dict(row))

cursor.execute("SELECT COUNT(*) FROM processes")
print("\nTotal saved process records:", cursor.fetchone()[0])

connection.close()
