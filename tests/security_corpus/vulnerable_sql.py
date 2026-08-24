import sqlite3

def lookup(user_input):
    conn = sqlite3.connect(":memory:")
    query = "SELECT * FROM users WHERE name = '%s'" % user_input
    return conn.execute(query).fetchall()
