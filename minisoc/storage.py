import sqlite3
import os

DATABASE = os.path.join(
    os.path.dirname(__file__),
    "minisoc.db",
)

def init_db():
    connection = sqlite3.connect(DATABASE)

    connection.execute("""
    CREATE TABLE IF NOT EXISTS alerts ( 
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    ip TEXT

    )
    """)
    connection.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY,
        ip TEXT NOT NULL,
        severity TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        status TEXT NOT NULL
    )
    """)
    connection.execute("""
    CREATE TABLE IF NOT EXISTS incident_rules (
        incident_id INTEGER NOT NULL,
        rule TEXT NOT NULL,
        PRIMARY KEY (incident_id, rule)
    )
    """)

    connection.commit()
    connection.close()

def save_alert(alert):
    connection = sqlite3.connect(DATABASE)

    connection.execute("""
    INSERT INTO alerts (
    timestamp, rule, severity, message, ip
    ) VALUES (?, ?, ?, ?, ?)
    """, (
        alert["timestamp"],
        alert["rule"],
        alert["severity"],
        alert["message"],
        alert.get("ip", None)
    ))
    connection.commit()
    connection.close()


def save_incident(incident):
    connection = sqlite3.connect(DATABASE)

    connection.execute("""
    INSERT INTO incidents (
        ip,
        severity,
        first_seen,
        last_seen,
        status
    ) VALUES (?, ?, ?, ?, ?)
    """, (
        incident["ip"],
        incident["severity"],
        incident["first_seen"],
        incident["last_seen"],
        incident["status"]
    ))

    connection.commit()
    incident_id = connection.execute(
    "SELECT last_insert_rowid()"
).fetchone()[0]
    connection.close()
    return incident_id

def update_incident(incident):
    connection = sqlite3.connect(DATABASE)

    connection.execute("""
    UPDATE incidents
    SET severity = ?,
        last_seen = ?,
        status = ?
    WHERE id = ?
    """, (
        incident["severity"],
        incident["last_seen"],
        incident["status"],
        incident["id"]
    ))
    

    connection.commit()
    connection.close()

def save_incident_rule(incident_id, rule):
    connection = sqlite3.connect(DATABASE)

    connection.execute("""
    INSERT OR IGNORE INTO incident_rules (
        incident_id,
        rule
    ) VALUES (?, ?)
    """, (
        incident_id,
        rule
    ))

    connection.commit()
    connection.close()


if __name__ == "__main__":
    init_db()
    print("Database initialized.")
