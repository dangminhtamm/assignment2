import sqlite3

conn = sqlite3.connect('comments.db')
cursor = conn.cursor()

cursor.execute("""
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        comment TEXT
    )
""")

conn.commit()
conn.close()

print("comments.db has been created with a table for storing comments.")
