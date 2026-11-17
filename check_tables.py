import sqlite3

connection = sqlite3.connect("reports/rdrs.db")

print("RDRS Database Tables:")

tables = connection.execute("""
    SELECT name
    FROM sqlite_master
    WHERE type = 'table'
    ORDER BY name
""").fetchall()

for table in tables:
    print("-", table[0])

connection.close()