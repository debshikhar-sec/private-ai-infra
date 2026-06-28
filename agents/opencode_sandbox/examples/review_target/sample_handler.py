"""A deliberately flawed sample handler, used as the default review target.

It exists so `run_review.sh` has something to point the read-only reviewer at out of
the box. The issues below are intentional — the point is to demonstrate the agent
*finding* them, not to ship good code.
"""

import sqlite3


def get_user(db_path, user_id):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    # Issue: SQL injection — user_id is interpolated into the query string.
    cur.execute("SELECT * FROM users WHERE id = '%s'" % user_id)
    row = cur.fetchone()
    # Issue: connection is never closed (resource leak on every call).
    return row


def make_token(secret, payload):
    # Issue: weak/no real signing; payload trusted without validation.
    return secret + ":" + str(payload)
