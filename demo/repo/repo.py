"""Data access - the sink."""


def query_user(user_id):
    cursor = connect()
    sql = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(sql)
    return cursor


def connect():
    import sqlite3

    return sqlite3.connect("app.db")
