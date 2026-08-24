import sqlite3

def lookup(user_input):
    conn = sqlite3.connect(":memory:")
    return conn.execute("SELECT * FROM users WHERE name = ?", (user_input,)).fetchall()
