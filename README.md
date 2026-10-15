# 🛡️ MiniSOC

A lightweight Security Operations Center (SOC) built from scratch. MiniSOC watches a Flask web
application's security log in real time, detects common web attacks using a custom rule-based
detection engine, correlates related events into incidents, and surfaces everything on a live,
auto-refreshing admin dashboard.

Built as a hands-on project to understand how detection and monitoring actually work under the
hood — both the defensive side (log parsing, rule-based detection, correlation, alerting) and the
offensive side (testing it against real attack tools from Kali Linux).

## How it works

```
EduPortal (Flask app)  --writes-->  security.log
                                         |
                                         v
                                  collector.py (tails the log)
                                         |
                                         v
                                  detector.py (rule engine)
                                         |
                                         v
                                  minisoc.db (SQLite)
                                         |
                                         v
                              Live admin dashboard (polls every 2s)
```

- **`eduportal/`** — the monitored web application (a small student portal). Logs security-relevant
  events: logins, failed logins, profile updates, document access, resource requests.
- **`minisoc/collector.py`** — tails `security.log` in real time and feeds each parsed event into
  the detector.
- **`minisoc/detector.py`** — rule-based detection engine. Flags suspicious patterns and, when
  multiple different attack types hit the same IP within a 5-minute window, opens a correlated
  incident linking them together.
- **`minisoc/storage.py`** — SQLite persistence for alerts, incidents, and incident-rule mappings.
- **Admin dashboard** — Flask-rendered pages that poll a JSON status endpoint every 2 seconds:
  live alert feed, severity-coded rows, an activity trend chart, a computed threat-level gauge,
  and a Top Attacking IPs leaderboard.

## Detected attack types

| Rule                          | Severity | Trigger                                                          |
|--------------------------------|----------|-------------------------------------------------------------------|
| `BRUTE_FORCE`                  | HIGH     | 5+ failed logins from the same IP within 60 seconds                |
| `ACCOUNT_ENUMERATION`          | HIGH     | 5+ different emails failing login from the same IP within 60s      |
| `SQLI_DETECTED`                | HIGH     | SQL injection patterns in the login email field                    |
| `XSS_DETECTED`                 | HIGH     | XSS payloads in profile update fields                               |
| `PATH_TRAVERSAL`                | HIGH     | Directory traversal sequences in resource requests                 |
| `UNAUTHORIZED_DOCUMENT_ACCESS`  | HIGH     | IDOR — accessing a document that isn't owned by the requesting user |
| `ENDPOINT_PROBING`              | MEDIUM   | 8+ different endpoints hit from the same IP within 60 seconds       |
| `CORRELATED_ATTACK`             | HIGH     | 2+ different rule types from the same IP within a 5-minute window — opens/updates an incident |

## Tech stack

Python · Flask · SQLite · vanilla JavaScript · Chart.js (live charts) · Jinja2 templates

Tested against: Hydra (brute force) and curl-based payload scripts (SQLi, XSS, path traversal,
IDOR, probing) from a Kali Linux attacker machine.

## Setup

```bash
git clone <your-repo-url>
cd MiniSOC

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Set a real secret key for session signing (don't use the dev fallback in anything but local testing)
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

python -m minisoc.storage   # creates minisoc.db
./run.sh                    # starts the app + the collector together
```

Then open `http://localhost:5000/minisoc` (after creating an account and logging in as an admin).

## Project structure

```
MiniSOC/
├── run.sh
├── eduportal/
│   ├── app.py
│   ├── templates/
│   └── static/
└── minisoc/
    ├── collector.py
    ├── detector.py
    ├── storage.py
    └── minisoc.db          (git-ignored, created at runtime)
```

## Known limitations

- Detection state (failed-login counts, active incidents, etc.) lives in memory in the collector
  process. Restarting the collector resets this state, and incidents are not automatically closed
  if traffic for that IP simply stops rather than continuing past the 5-minute correlation window.
- This is a learning project, not a production security tool. Rules are intentionally simple
  (regex/threshold based) rather than using statistical or ML-based anomaly detection.

## Why I built this

To understand detection engineering from the ground up — writing the rules myself rather than
configuring an existing SIEM, and then validating the system by attacking it with real offensive
tooling (Hydra, curl-crafted payloads) from a separate Kali Linux machine.
