
import re
from datetime import datetime, timedelta

from minisoc.storage import (
    save_incident,
    update_incident,
    save_incident_rule
)


failed_logins = {}
brute_force_alerted = set()
enumeration_attempts = {}
endpoint_probes = {}
correlation_events = {}
active_incidents = {}


CORRELATION_RULES = {
    "SQLI_DETECTED",
    "XSS_DETECTED",
    "PATH_TRAVERSAL",
    "BRUTE_FORCE",
    "ACCOUNT_ENUMERATION",
    "ENDPOINT_PROBING",
    "UNAUTHORIZED_DOCUMENT_ACCESS"
}


def detect_sqli(value):

    patterns = [
        r"\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"\band\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"union\s+select",
        r"select\s+.+\s+from",
        r"drop\s+table",
        r"insert\s+into",
        r"delete\s+from",
        r"--",
        r"/\*",
        r"\*/"
    ]

    value = value.lower()

    for pattern in patterns:
        if re.search(pattern, value):
            return True

    return False


def detect_xss(value):

    xss_patterns = [
        r"<script.*?>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<img\s+src=.*?>",
        r"<iframe.*?>.*?</iframe>",
        r"<svg.*?>.*?</svg>",
        r"<body.*?>.*?</body>",
        r"<object.*?>.*?</object>",
        r"<embed.*?>.*?</embed>"
    ]

    value = value.lower()

    for pattern in xss_patterns:
        if re.search(pattern, value):
            return True

    return False


def detect_path_traversal(value):

    patterns = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e%5c",
        r"\.\.%2f",
        r"\.\.%5c"
    ]

    value = value.lower()

    for pattern in patterns:
        if re.search(pattern, value):
            return True

    return False


def detect_account_enumeration(ip, email, timestamp):

    timestamp = datetime.strptime(
        timestamp,
        "%Y-%m-%d %H:%M:%S,%f"
    )

    if ip not in enumeration_attempts:
        enumeration_attempts[ip] = []

    enumeration_attempts[ip].append(
        (email, timestamp)
    )

    window_start = timestamp - timedelta(seconds=60)

    recent_attempts = [
        attempt
        for attempt in enumeration_attempts[ip]
        if attempt[1] >= window_start
    ]

    unique_emails = set(
        attempt[0]
        for attempt in recent_attempts
    )

    if len(unique_emails) >= 5:
        return True

    return False


def detect_endpoint_probing(ip, endpoint, timestamp):

    timestamp = datetime.strptime(
        timestamp,
        "%Y-%m-%d %H:%M:%S,%f"
    )

    if ip not in endpoint_probes:
        endpoint_probes[ip] = []

    endpoint_probes[ip].append(
        (endpoint, timestamp)
    )

    window_start = timestamp - timedelta(seconds=60)

    recent_probes = [
        probe
        for probe in endpoint_probes[ip]
        if probe[1] >= window_start
    ]

    unique_endpoints = set(
        probe[0]
        for probe in recent_probes
    )

    if len(unique_endpoints) >= 10:
        return True

    return False


def track_suspicious_event(ip, rule, timestamp):

    timestamp = datetime.strptime(
        timestamp,
        "%Y-%m-%d %H:%M:%S,%f"
    )

    if ip not in correlation_events:
        correlation_events[ip] = []

    correlation_events[ip].append(
        (rule, timestamp)
    )

    window_start = timestamp - timedelta(minutes=5)

    recent_events = [
        event
        for event in correlation_events[ip]
        if event[1] >= window_start
    ]

    # Keep only the recent events in memory.
    correlation_events[ip] = recent_events

    return recent_events


def detect_correlation(ip, rule, timestamp):

    recent_events = track_suspicious_event(
        ip,
        rule,
        timestamp
    )

    unique_rules = set(
        event[0]
        for event in recent_events
    )

    # Need at least 2 different suspicious rules.
    if len(unique_rules) < 2:
        return None

    current_time = datetime.strptime(
        timestamp,
        "%Y-%m-%d %H:%M:%S,%f"
    )

    # Existing active incident for this IP.
    if ip in active_incidents:

        incident = active_incidents[ip]

        # Incident is still active.
        if current_time - incident["last_seen"] <= timedelta(minutes=5):

            new_rules = unique_rules - incident["rules"]

            incident["rules"].update(new_rules)

            # Persist newly discovered rules.
            for new_rule in new_rules:
                save_incident_rule(
                    incident["id"],
                    new_rule
                )

            incident["last_seen"] = current_time

            update_incident({
                "id": incident["id"],
                "severity": "HIGH",
                "last_seen": current_time.strftime(
                    "%Y-%m-%d %H:%M:%S,%f"
                ),
                "status": "OPEN"
            })

            return {
                "incident_id": incident["id"],
                "rules": list(incident["rules"]),
                "updated": True
            }

        # Incident expired after 5 minutes
        # of inactivity.
        update_incident({
            "id": incident["id"],
            "severity": "HIGH",
            "last_seen": incident["last_seen"].strftime(
                "%Y-%m-%d %H:%M:%S,%f"
            ),
            "status": "CLOSED"
        })

        del active_incidents[ip]

        # Remove old correlation history so that
        # the new attack starts cleanly.
        correlation_events[ip] = [
            event
            for event in recent_events
            if event[1] >= current_time - timedelta(minutes=5)
        ]

    # No active incident → create a new one.

    first_seen = min(
        event[1]
        for event in recent_events
    )

    incident_id = save_incident({
        "ip": ip,
        "severity": "HIGH",
        "first_seen": first_seen.strftime(
            "%Y-%m-%d %H:%M:%S,%f"
        ),
        "last_seen": current_time.strftime(
            "%Y-%m-%d %H:%M:%S,%f"
        ),
        "status": "OPEN"
    })

    active_incidents[ip] = {
        "id": incident_id,
        "rules": set(unique_rules),
        "first_seen": first_seen,
        "last_seen": current_time
    }

    for correlated_rule in unique_rules:
        save_incident_rule(
            incident_id,
            correlated_rule
        )

    return {
        "incident_id": incident_id,
        "rules": list(unique_rules),
        "updated": False
    }


def detect_event_rules(event_data):

    if event_data["event"] == "RESOURCE_ACCESS":

        value = event_data.get(
            "resource",
            ""
        )

        if detect_path_traversal(value):

            return {
                "alert": True,
                "rule": "PATH_TRAVERSAL",
                "severity": "HIGH",
                "message": (
                    f"Possible path traversal attempt: "
                    f"{value} from "
                    f"{event_data.get('ip')}"
                )
            }

    if event_data["event"] == "PROFILE_UPDATE":

        full_name = event_data.get("full_name", "")
        phone = event_data.get("phone", "")

        for field_name, value in [("full_name", full_name), ("phone", phone)]:

            if detect_xss(value):

                return {
                    "alert": True,
                    "rule": "XSS_DETECTED",
                    "severity": "HIGH",
                    "message": (
                        f"XSS attempt detected in {field_name} field: "
                        f"{value} from "
                        f"{event_data.get('ip')}"
                    )
                }

    if event_data["event"] == "UNAUTHORIZED_DOCUMENT_ACCESS":

        return {
            "alert": True,
            "rule": "UNAUTHORIZED_DOCUMENT_ACCESS",
            "severity": "HIGH",
            "message": (
                f"Unauthorized document access attempt: "
                f"document_id="
                f"{event_data.get('document_id')} "
                f"user_id="
                f"{event_data.get('user_id')} "
                f"owner_id="
                f"{event_data.get('owner_id')}"
            )
        }

    if event_data["event"] == "LOGIN_FAILURE":

        # Account enumeration detection.

        email = event_data.get(
            "email",
            ""
        )

        if detect_account_enumeration(
            event_data["ip"],
            email,
            event_data["timestamp"]
        ):

            return {
                "alert": True,
                "rule": "ACCOUNT_ENUMERATION",
                "severity": "HIGH",
                "message": (
                    f"Possible account enumeration attempt: "
                    f"multiple failed logins for different "
                    f"emails from {event_data['ip']} "
                    f"within 60 seconds"
                )
            }

        # SQL injection detection.

        if detect_sqli(email):

            return {
                "alert": True,
                "rule": "SQLI_DETECTED",
                "severity": "HIGH",
                "message": (
                    f"SQL injection attempt detected "
                    f"in email field: {email}"
                )
            }

        # Brute-force attack detection.

        ip = event_data["ip"]

        timestamp = datetime.strptime(
            event_data["timestamp"],
            "%Y-%m-%d %H:%M:%S,%f"
        )

        if ip not in failed_logins:
            failed_logins[ip] = []

        failed_logins[ip].append(timestamp)

        window_start = timestamp - timedelta(seconds=60)

        recent_failures = [
            attempt
            for attempt in failed_logins[ip]
            if attempt >= window_start
        ]

        # Keep only the recent attempts so the list doesn't grow forever.
        failed_logins[ip] = recent_failures

        # Attack has calmed down: allow a future brute force to alert again.
        if len(recent_failures) < 5:
            brute_force_alerted.discard(ip)

        # High severity: brute-force detected.

        if len(recent_failures) >= 5:

            if ip not in brute_force_alerted:

                brute_force_alerted.add(ip)

                return {
                    "alert": True,
                    "rule": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "message": (
                        f"Possible brute-force attack: "
                        f"{len(recent_failures)} failed logins "
                        f"from {ip} within 60 seconds"
                    )
                }

            # Already alerted for this attack.

            return None

        # Medium severity: repeated failures.

        if len(recent_failures) >= 4:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "alert": True,
            "rule": "LOGIN_FAILURE",
            "severity": severity,
            "message": (
                f"Failed login attempt "
                f"#{len(recent_failures)} detected"
            )
        }

    if event_data["event"] == "ENDPOINT_ACCESS":

        endpoint = event_data.get(
            "endpoint",
            ""
        )

        if detect_endpoint_probing(
            event_data["ip"],
            endpoint,
            event_data["timestamp"]
        ):

            return {
                "alert": True,
                "rule": "ENDPOINT_PROBING",
                "severity": "MEDIUM",
                "message": (
                    f"Possible endpoint probing attempt: "
                    f"multiple accesses to different "
                    f"endpoints from {event_data['ip']} "
                    f"within 60 seconds"
                )
            }

    return None


def detect_event(event_data):

    result = detect_event_rules(event_data)

    if result:

        print(
            "Suspicious event detected:",
            result["rule"]
        )

        if result["rule"] in CORRELATION_RULES:

            correlation = detect_correlation(
                event_data["ip"],
                result["rule"],
                event_data["timestamp"]
            )

            if correlation:

                rules = ", ".join(
                    correlation["rules"]
                )

                if correlation["updated"]:

                    message = (
                        f"Incident #"
                        f"{correlation['incident_id']} "
                        f"updated: multiple suspicious "
                        f"activities detected from "
                        f"{event_data['ip']} within 5 minutes: "
                        f"{rules}"
                    )

                else:

                    message = (
                        f"Incident #"
                        f"{correlation['incident_id']} "
                        f"created: multiple suspicious "
                        f"activities detected from "
                        f"{event_data['ip']} within 5 minutes: "
                        f"{rules}"
                    )

                return {
                    "alert": True,
                    "rule": "CORRELATED_ATTACK",
                    "severity": "HIGH",
                    "message": message,
                    "incident_id": correlation["incident_id"],
                    "correlated_rules": correlation["rules"]
                }

    return result