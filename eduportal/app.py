from flask import Flask, render_template , request , redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3
import logging
import os


def get_client_ip():
    return request.remote_addr

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-fallback-change-me")


logging.basicConfig(
    filename="security.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

@app.before_request
def log_endpoint_access():

    if request.path.startswith("/static/"):
        return

    if request.path.startswith("/minisoc/events"):
        return

    if request.path.startswith("/minisoc/api/"):
        return

    logging.info(
        f"ENDPOINT_ACCESS | "
        f"endpoint={request.path} | "
        f"ip={get_client_ip()}"
    )

def login_required(route_function):
    @wraps(route_function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return "You are not logged in"

        return route_function(*args, **kwargs)

    return wrapper

def admin_required(route_function):
    @wraps(route_function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:
            return "You are not logged in", 401

        db = get_db()

        user = db.execute(
            """
            SELECT role
            FROM users
            WHERE id = ?
            """,
            (session["user_id"],)
        ).fetchone()

        db.close()

        if user is None or user["role"] != "admin":
            return "Forbidden: administrator access required", 403

        return route_function(*args, **kwargs)

    return wrapper

def get_db():
    connection = sqlite3.connect("eduportal.db")
    connection.row_factory = sqlite3.Row
    return connection
def get_minisoc_db():
    db_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "minisoc",
        "minisoc.db"
    )

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row

    return connection

@app.route("/minisoc")
@login_required
@admin_required
def minisoc_dashboard():
    

    db = get_minisoc_db()

    alerts = db.execute("""
        SELECT *
        FROM alerts
        ORDER BY id DESC
        LIMIT 10
    """).fetchall()

    incidents = db.execute("""
        SELECT *
        FROM incidents
        ORDER BY id DESC
        LIMIT 10
    """).fetchall()

    db.close()

    return render_template(
        "minisoc_dashboard.html",
        alerts=alerts,
        incidents=incidents
    )
@app.route("/minisoc/api/alerts")
@login_required
@admin_required
def minisoc_api_alerts():

    db = get_minisoc_db()

    alerts = db.execute("""
        SELECT *
        FROM alerts
        ORDER BY id DESC
        LIMIT 10
    """).fetchall()

    db.close()

    return {
        "alerts": [dict(alert) for alert in alerts]
    }
@app.route("/minisoc/api/status")
@login_required
@admin_required
def minisoc_api_status():

    db = get_minisoc_db()

    alerts = db.execute("""
        SELECT *
        FROM alerts
        ORDER BY id DESC
        LIMIT 10
    """).fetchall()

    incidents = db.execute("""
        SELECT *
        FROM incidents
        ORDER BY id DESC
        LIMIT 10
    """).fetchall()

    total_alerts = db.execute("""
        SELECT COUNT(*)
        FROM alerts
    """).fetchone()[0]

    high_alerts = db.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'HIGH'
    """).fetchone()[0]

    medium_alerts = db.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'MEDIUM'
    """).fetchone()[0]

    low_alerts = db.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'LOW'
    """).fetchone()[0]

    open_incidents = db.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE status = 'OPEN'
    """).fetchone()[0]

    # Last 100 alerts, used to build the activity trend chart.
    trend_rows = db.execute("""
        SELECT timestamp
        FROM alerts
        ORDER BY id DESC
        LIMIT 100
    """).fetchall()

    db.close()

    # Bucket alerts by minute (last 15 minutes) for the trend chart.
    from datetime import datetime, timedelta

    latest = None
    buckets = {}

    for row in trend_rows:
        try:
            ts = datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S,%f")
        except ValueError:
            continue
        if latest is None or ts > latest:
            latest = ts
        key = ts.strftime("%H:%M")
        buckets[key] = buckets.get(key, 0) + 1

    trend = []
    if latest:
        for i in range(14, -1, -1):
            minute = latest - timedelta(minutes=i)
            key = minute.strftime("%H:%M")
            trend.append({"label": key, "count": buckets.get(key, 0)})

    return {
        "alerts": [dict(alert) for alert in alerts],
        "incidents": [dict(incident) for incident in incidents],
        "stats": {
            "total_alerts": total_alerts,
            "high_alerts": high_alerts,
            "medium_alerts": medium_alerts,
            "low_alerts": low_alerts,
            "open_incidents": open_incidents
        },
        "trend": trend
    }
@app.route("/minisoc/alerts")
@login_required
@admin_required
def minisoc_alerts():

    db = get_minisoc_db()

    alerts = db.execute("""
        SELECT *
        FROM alerts
        ORDER BY id DESC
    """).fetchall()

    db.close()

    return render_template(
        "admin_alerts.html",
        alerts=alerts
    )
@app.route("/minisoc/incidents")
@login_required
@admin_required
def minisoc_incidents():

    db = get_minisoc_db()

    incidents = db.execute("""
        SELECT *
        FROM incidents
        ORDER BY id DESC
    """).fetchall()

    incidents = [dict(incident) for incident in incidents]

    for incident in incidents:

        rules = db.execute("""
            SELECT rule
            FROM incident_rules
            WHERE incident_id = ?
            ORDER BY rule
        """, (incident["id"],)).fetchall()

        incident["rules"] = [
            rule["rule"]
            for rule in rules
        ]

    db.close()

    return render_template(
        "admin_incidents.html",
        incidents=incidents
    )
@app.route("/minisoc/events")
@login_required
@admin_required
def minisoc_events():

    log_path = os.path.join(
        os.path.dirname(__file__),
        "security.log"
    )

    try:
        with open(log_path, "r", encoding="utf-8") as log_file:
            events = log_file.readlines()

    except FileNotFoundError:
        events = []

    events = events[-200:]
    events.reverse()

    return render_template(
        "admin_events.html",
        events=events
    )
@app.route("/minisoc/investigation")
@login_required
@admin_required
def minisoc_investigation():

    ip = request.args.get("ip", "").strip()

    alerts = []
    incidents = []

    if ip:

        db = get_minisoc_db()

        alerts = db.execute("""
            SELECT *
            FROM alerts
            WHERE ip = ?
            ORDER BY id DESC
        """, (ip,)).fetchall()

        incidents = db.execute("""
            SELECT *
            FROM incidents
            WHERE ip = ?
            ORDER BY id DESC
        """, (ip,)).fetchall()

        db.close()

    return render_template(
        "admin_investigation.html",
        ip=ip,
        alerts=alerts,
        incidents=incidents
    )

def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            phone TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.execute("""
    CREATE TABLE IF NOT EXISTS courses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        description TEXT
    )
""")
    db.execute("""
    CREATE TABLE IF NOT EXISTS student_courses (
        student_id INTEGER NOT NULL,
        course_id INTEGER NOT NULL,
        FOREIGN KEY (student_id) REFERENCES users(id),
        FOREIGN KEY (course_id) REFERENCES courses(id),
        PRIMARY KEY (student_id, course_id)
    )
""")
    db.execute("""
    CREATE TABLE IF NOT EXISTS grades (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        course_id INTEGER NOT NULL,
        grade REAL NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (student_id) REFERENCES users(id),
        FOREIGN KEY (course_id) REFERENCES courses(id)
    )
""")
    db.execute("""
CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    course_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    status TEXT NOT NULL,
    FOREIGN KEY (student_id) REFERENCES users(id),
    FOREIGN KEY (course_id) REFERENCES courses(id)
)
""")
    db.execute("""
CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    document_type TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (student_id) REFERENCES users(id)
)
""")
    db.commit()
    db.close()  
def seed_courses():
    db = get_db()

    courses = [
        ("WEB101", "Web Development", "HTML, CSS, JavaScript and Flask"),
        ("DB101", "Database Systems", "SQL, SQLite and database design"),
        ("SEC101", "Cybersecurity", "Introduction to cybersecurity concepts"),
        ("PY101", "Python Programming", "Python programming fundamentals")
    ]

    db.executemany(
        """
        INSERT OR IGNORE INTO courses (code, name, description)
        VALUES (?, ?, ?)
        """,
        courses
    )

    db.commit()
    db.close()
def seed_student_courses():
    db = get_db()

    db.execute(
        """
        INSERT OR IGNORE INTO student_courses (student_id, course_id)
        SELECT users.id, courses.id
        FROM users, courses
        WHERE users.student_id = ? AND courses.code = ?
        """,
        ("12345655", "WEB101")
    )

    db.commit()
    db.close()

def seed_grades():
    db = get_db()

    db.execute(
        """
        INSERT INTO grades (student_id, course_id, grade)
        SELECT users.id, courses.id, ?
        FROM users, courses
        WHERE users.student_id = ? AND courses.code = ?
        AND NOT EXISTS (
            SELECT 1
            FROM grades
            WHERE grades.student_id = users.id
            AND grades.course_id = courses.id
        )
        """,
        (15.5, "12345655", "WEB101")
    )

    db.commit()
    db.close()
def seed_attendance():
    db = get_db()

    db.execute(
        """
        INSERT INTO attendance (student_id, course_id, date, status)
        SELECT users.id, courses.id, ?, ?
        FROM users, courses
        WHERE users.student_id = ? AND courses.code = ?
        AND NOT EXISTS (
            SELECT 1
            FROM attendance
            WHERE attendance.student_id = users.id
            AND attendance.course_id = courses.id
            AND attendance.date = ?
        )
        """,
        ("2026-10-01", "Present", "12345655", "WEB101", "2026-10-01")
    )

    db.commit()
    db.close()
def seed_documents():
    db = get_db()

    db.execute(
        """
        INSERT INTO documents (student_id, name, document_type)
        SELECT users.id, ?, ?
        FROM users
        WHERE users.student_id = ?
        AND NOT EXISTS (
            SELECT 1
            FROM documents
            WHERE documents.student_id = users.id
            AND documents.name = ?
        )
        """,
        (
            "Web Development Grade Report",
            "Grade Report",
            "12345655",
            "Web Development Grade Report"
        )
    )

    db.commit()
    db.close()

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    if request.method == "POST":
        print("POST REQUEST RECEIVED")
        student_id = request.form.get("student_id")
        full_name = request.form.get("full_name")
        email = request.form.get("email")
        phone = request.form.get("phone")
        password = request.form.get("password")
        if not student_id or not full_name or not password :
            return "Missing required fields"
        hashed_password = generate_password_hash(password)
    db = get_db()

    try:
        db.execute("""
        INSERT INTO users (student_id, full_name, email, password, phone)
        VALUES (?, ?, ?, ?, ?)
    """, (student_id, full_name, email, hashed_password, phone))

        db.commit()
        logging.info(
    f"REGISTER | student_id={student_id} | ip={get_client_ip()}"
)

    except sqlite3.IntegrityError:
        db.close()
        return "Student ID or email already exists"

    db.close()
    return redirect(url_for("login"))

    
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        db = get_db()

        user = db.execute(
    "SELECT id, student_id, full_name, email, password, role FROM users WHERE email = ?",
    (email,)
).fetchone()

        db.close()

        if user is None:
            logging.warning(
                f"LOGIN_FAILURE | email={email} | ip={get_client_ip()}"
            )
            return render_template("login.html", login_error="Invalid email or password") 
        

        if not check_password_hash(user[4], password):
            logging.warning(
                            f"LOGIN_FAILURE | email={email} | ip={get_client_ip()}"
                        )
            return render_template("login.html", login_error="Invalid email or password") 
        session["user_id"] = user[0]
        logging.info(
    f"LOGIN_SUCCESS | user_id={user[0]} | ip={get_client_ip()}"
)
        if user[5] == "admin":
            return redirect(url_for("minisoc_dashboard"))
        return redirect(url_for("dashboard"))
    
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():

    if request.method == "POST":
        full_name = request.form.get("full_name", "")
        phone = request.form.get("phone", "")

        logging.info(
            f"PROFILE_UPDATE | user_id={session['user_id']} "
            f"| full_name={full_name} | phone={phone} "
            f"| ip={get_client_ip()}"
        )

        db = get_db()

        db.execute(
            "UPDATE users SET full_name = ?, phone = ? WHERE id = ?",
            (full_name, phone, session["user_id"])
        )

        db.commit()
        db.close()

        return redirect(url_for("profile"))

    db = get_db()

    user = db.execute(
        "SELECT student_id, full_name, email, phone FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    db.close()

    if user is None:
        return "User not found"

    logging.info(
        f"PROFILE_ACCESS | user_id={session['user_id']} | ip={get_client_ip()}"
    )

    return render_template("profile.html", user=user)

@app.route("/logout")
def logout():
    user_id = session.get("user_id")
    logging.info(
        f"LOGOUT | user_id={user_id} | ip={get_client_ip()}"
    )
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()

    user = db.execute(
        "SELECT student_id, full_name, email, phone FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    courses = db.execute(
        """
        SELECT courses.code, courses.name
        FROM courses
        JOIN student_courses
            ON courses.id = student_courses.course_id
        WHERE student_courses.student_id = ?
        """,
        (session["user_id"],)
    ).fetchall()

    db.close()

    if user is None:
        return "User not found"

    return render_template(
        "dashboard.html",
        user=user,
        courses=courses
    )
@app.route("/courses")
@login_required
def courses():
    db = get_db()

    courses = db.execute(
    """
    SELECT courses.id, courses.code, courses.name, courses.description
    FROM courses
    JOIN student_courses
        ON courses.id = student_courses.course_id
    WHERE student_courses.student_id = ?
    """,
    (session["user_id"],)
).fetchall()
    db.close()

    logging.info(
    f"COURSE_ACCESS | user_id={session['user_id']} | ip={get_client_ip()}"
)

    return render_template("courses.html", courses=courses)

@app.route("/grades")
@login_required
def grades():
    db = get_db()

    grades = db.execute(
        """
        SELECT courses.code, courses.name, grades.grade
        FROM grades
        JOIN courses
            ON grades.course_id = courses.id
        WHERE grades.student_id = ?
        """,
        (session["user_id"],)
    ).fetchall()

    average = db.execute(
        """
        SELECT AVG(grade)
        FROM grades
        WHERE student_id = ?
        """,
        (session["user_id"],)
    ).fetchone()[0]

    db.close()
    logging.info(
    f"GRADE_ACCESS | user_id={session['user_id']} | ip={get_client_ip()}"
)

    return render_template(
        "grades.html",
        grades=grades,
        average=average
    )


@app.route("/attendance")
@login_required
def attendance():
    db = get_db()

    attendance = db.execute(
        """
        SELECT courses.code, courses.name, attendance.date, attendance.status
        FROM attendance
        JOIN courses
            ON attendance.course_id = courses.id
        WHERE attendance.student_id = ?
        ORDER BY attendance.date DESC
        """,
        (session["user_id"],)
    ).fetchall()

    db.close()
    logging.info(
    f"ATTENDANCE_ACCESS | user_id={session['user_id']} | ip={get_client_ip()}"
)

    return render_template("attendance.html", attendance=attendance)

@app.route("/documents")
@login_required
def documents():
    db = get_db()

    documents = db.execute(
        """
        SELECT id, name, document_type, created_at
        FROM documents
        WHERE student_id = ?
        ORDER BY created_at DESC
        """,
        (session["user_id"],)
    ).fetchall()

    db.close()
    logging.info(
    f"DOCUMENTS_ACCESS | user_id={session['user_id']} | ip={get_client_ip()}"
)

    return render_template("documents.html", documents=documents)

@app.route("/documents/<int:document_id>")
@login_required
def document_access(document_id):

    db = get_db()

    document = db.execute(
        """
        SELECT id, student_id, name, document_type, created_at
        FROM documents
        WHERE id = ?
        """,
        (document_id,)
    ).fetchone()

    db.close()

    # Document does not exist
    if document is None:

        logging.warning(
            f"DOCUMENT_NOT_FOUND | "
            f"document_id={document_id} | "
            f"user_id={session['user_id']} | "
            f"ip={get_client_ip()}"
        )

        return "Document not found", 404

    # Authorization check
    if document[1] != session["user_id"]:

        logging.warning(
            f"UNAUTHORIZED_DOCUMENT_ACCESS | "
            f"document_id={document_id} | "
            f"owner_id={document[1]} | "
            f"user_id={session['user_id']} | "
            f"ip={get_client_ip()}"
        )

        return "Unauthorized document access", 403

    # Authorized document access
    logging.info(
        f"DOCUMENT_ACCESS | "
        f"document_id={document[0]} | "
        f"user_id={session['user_id']} | "
        f"ip={get_client_ip()}"
    )

    return render_template(
        "document.html",
        document=document
    )

@app.route("/resource")
@login_required
def resource_access():

    resource = request.args.get("file", "")

    logging.info(
        f"RESOURCE_ACCESS | "
        f"resource={resource} | "
        f"user_id={session['user_id']} | "
        f"ip={get_client_ip()}"
    )

    return f"Resource requested: {resource}"

init_db()
seed_courses()
seed_student_courses()
seed_grades()
seed_attendance()
seed_documents()
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=os.environ.get("FLASK_DEBUG") == "1"
    )