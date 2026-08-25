import sqlite3


def vulnerable(conn, user_input):
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    return conn.execute(query).fetchall()


def safe(conn, user_input):
    return conn.execute("SELECT * FROM users WHERE name = ?", (user_input,)).fetchall()
