
import json
import re
from datetime import datetime


# ============================================================
# CONFIGURATION
# ============================================================

FAILED_LOGIN_THRESHOLD = 3
BRUTE_FORCE_WINDOW_MINUTES = 5
SUCCESS_CORRELATION_WINDOW_MINUTES = 10


WINDOWS_EVENT_ACTIONS = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4740: "Account Locked Out"
}


# ============================================================
# TIMESTAMP CONVERSION
# ============================================================

def convert_timestamp(time_string):
    """
    Converts Windows timestamp such as:

    /Date(1783333954871)/

    into:

    YYYY-MM-DD HH:MM:SS
    """

    match = re.search(r"\d+", str(time_string))

    if match:
        milliseconds = int(match.group())

        return datetime.fromtimestamp(
            milliseconds / 1000
        ).strftime("%Y-%m-%d %H:%M:%S")

    return "N/A"


def parse_timestamp(timestamp):
    """
    Convert standardized timestamp string into datetime object.
    """

    if not timestamp or timestamp == "N/A":
        return None

    try:
        return datetime.strptime(
            timestamp,
            "%Y-%m-%d %H:%M:%S"
        )

    except ValueError:
        return None


# ============================================================
# WINDOWS LOG NORMALIZATION
# ============================================================

def normalize_windows(raw_log):
    """
    Converts a Windows Security Event into
    the standard SOC engine schema.
    """

    event_id = raw_log.get("EventID")

    return {
        "timestamp": convert_timestamp(
            raw_log.get("TimeCreated", "")
        ),

        "normalized_ip": raw_log.get(
            "IpAddress",
            "N/A"
        ),

        "event_id": event_id,

        "event_action": WINDOWS_EVENT_ACTIONS.get(
            event_id,
            f"Event ID {event_id}"
        ),

        "username": raw_log.get(
            "TargetUserName",
            "N/A"
        ),

        "workstation": raw_log.get(
            "WorkstationName",
            "N/A"
        ),

        "logon_type": raw_log.get(
            "LogonType",
            "N/A"
        ),

        "status": raw_log.get(
            "Status",
            "N/A"
        ),

        "computer_name": raw_log.get(
            "Computer",
            "N/A"
        ),

        "log_source": "Windows",

        "raw_data": raw_log
    }


# ============================================================
# LOG INGESTION
# ============================================================

def ingest_and_normalize():

    standardized_logs = []

    # --------------------------------------------------------
    # Windows Logs
    # --------------------------------------------------------

    try:

        with open(
            "windows_logs.json",
            "r"
        ) as file:

            windows_data = json.load(file)

            for raw_log in windows_data:

                standardized_logs.append(
                    normalize_windows(raw_log)
                )

    except FileNotFoundError:

        print(
            "[WARNING] windows_logs.json not found."
        )

    except json.JSONDecodeError:

        print(
            "[ERROR] windows_logs.json contains invalid JSON."
        )

    return standardized_logs

# ============================================================
# ALERT GENERATION
# ============================================================

def generate_alert(
    alert_type,
    severity,
    username,
    source_ip,
    workstation,
    attempts,
    timestamp,
    rule_id,
    mitre_id,
    description,
    recommended_action
):

    return {

        "alert_id": None,

        "type": alert_type,

        "severity": severity,

        "username": username,

        "source_ip": source_ip,

        "workstation": workstation,

        "attempts": attempts,

        "timestamp": timestamp,

        "rule_id": rule_id,

        "mitre_attack": mitre_id,

        "description": description,

        "recommended_action": recommended_action
    }


# ============================================================
# RULE 1 — BRUTE FORCE DETECTION
# ============================================================

def detect_failed_logins(logs):

    alerts = []

    failed_events = {}

    for log in logs:

        if log.get("event_id") != 4625:
            continue

        ip = log.get(
            "normalized_ip",
            "N/A"
        )

        username = log.get(
            "username",
            "N/A"
        )

        timestamp = parse_timestamp(
            log.get("timestamp")
        )

        # Ignore missing IPs
        if not ip or ip == "N/A":
            continue

        # Ignore localhost for remote brute-force detection
        if ip == "127.0.0.1":
            continue

        if timestamp is None:
            continue

        key = (
            ip,
            username
        )

        if key not in failed_events:

            failed_events[key] = []

        failed_events[key].append(
            {
                "timestamp": timestamp,
                "log": log
            }
        )


    # --------------------------------------------------------
    # Check each IP + username combination
    # --------------------------------------------------------

    for key, events in failed_events.items():

        events.sort(
            key=lambda x: x["timestamp"]
        )

        for i in range(
            len(events)
        ):

            window_start = events[i]["timestamp"]

            window_events = []

            for event in events[i:]:

                difference = (
                    event["timestamp"]
                    - window_start
                ).total_seconds() / 60

                if difference <= BRUTE_FORCE_WINDOW_MINUTES:

                    window_events.append(event)

                else:

                    break


            if len(window_events) >= FAILED_LOGIN_THRESHOLD:

                first_event = window_events[0]["log"]

                alert = generate_alert(

                    alert_type="Brute Force",

                    severity="HIGH",

                    username=key[1],

                    source_ip=key[0],

                    workstation=first_event.get(
                        "workstation",
                        "N/A"
                    ),

                    attempts=len(window_events),

                    timestamp=first_event.get(
                        "timestamp",
                        "N/A"
                    ),

                    rule_id="R001",

                    mitre_id="T1110",

                    description=(
                        "Multiple failed authentication "
                        "attempts detected from the same "
                        "source against the same account."
                    ),

                    recommended_action=(
                        "Investigate the source IP, "
                        "review authentication activity, "
                        "and consider blocking or rate-limiting "
                        "the source."
                    )
                )

                alerts.append(alert)

                # Prevent duplicate alerts for
                # overlapping windows
                break


    return alerts


# ============================================================
# RULE 2 — ACCOUNT LOCKOUT
# ============================================================

def detect_account_lockout(logs):

    alerts = []

    for log in logs:

        if log.get("event_id") != 4740:
            continue

        alert = generate_alert(

            alert_type="Account Lockout",

            severity="MEDIUM",

            username=log.get(
                "username",
                "N/A"
            ),

            source_ip=log.get(
                "normalized_ip",
                "N/A"
            ),

            workstation=log.get(
                "workstation",
                "N/A"
            ),

            attempts="N/A",

            timestamp=log.get(
                "timestamp",
                "N/A"
            ),

            rule_id="R002",

            mitre_id="T1110",

            description=(
                "A Windows account lockout event "
                "was detected."
            ),

            recommended_action=(
                "Verify whether the lockout was caused "
                "by legitimate activity or repeated "
                "authentication failures."
            )
        )

        alerts.append(alert)


    return alerts


# ============================================================
# RULE 3 — FAILED LOGIN FOLLOWED BY SUCCESS
# ============================================================

def detect_failed_then_successful(logs):

    alerts = []

    # Sort logs chronologically
    sorted_logs = sorted(
        logs,
        key=lambda log: log.get(
            "timestamp",
            ""
        )
    )

    for index, log in enumerate(sorted_logs):

        if log.get("event_id") != 4624:
            continue

        success_time = parse_timestamp(
            log.get("timestamp")
        )

        if success_time is None:
            continue

        success_ip = log.get(
            "normalized_ip",
            "N/A"
        )

        success_user = log.get(
            "username",
            "N/A"
        )

        failed_attempts = []

        # Search backwards for related 4625 events
        for previous_log in reversed(
            sorted_logs[:index]
        ):

            if previous_log.get(
                "event_id"
            ) != 4625:

                continue

            failed_time = parse_timestamp(
                previous_log.get(
                    "timestamp"
                )
            )

            if failed_time is None:
                continue

            difference = (
                success_time
                - failed_time
            ).total_seconds() / 60

            if difference > SUCCESS_CORRELATION_WINDOW_MINUTES:
                break

            previous_ip = previous_log.get(
                "normalized_ip",
                "N/A"
            )

            previous_user = previous_log.get(
                "username",
                "N/A"
            )

            if (
                previous_ip == success_ip
                and
                previous_user == success_user
            ):

                failed_attempts.append(
                    previous_log
                )


        # Require at least 3 failures
        if len(failed_attempts) >= FAILED_LOGIN_THRESHOLD:

            alert = generate_alert(

                alert_type=(
                    "Brute Force Followed "
                    "by Successful Login"
                ),

                severity="CRITICAL",

                username=success_user,

                source_ip=success_ip,

                workstation=log.get(
                    "workstation",
                    "N/A"
                ),

                attempts=len(failed_attempts),

                timestamp=log.get(
                    "timestamp",
                    "N/A"
                ),

                rule_id="R003",

                mitre_id="T1110",

                description=(
                    "Multiple failed authentication "
                    "attempts were followed by a "
                    "successful authentication from "
                    "the same source against the same account."
                ),

                recommended_action=(
                    "Investigate the successful login, "
                    "validate the user's activity, "
                    "review the source IP, and reset "
                    "credentials if compromise is suspected."
                )
            )

            alerts.append(alert)


    return alerts


# ============================================================
# CORRELATION — BRUTE FORCE + ACCOUNT LOCKOUT
# ============================================================

def correlate_bruteforce_lockout(
    brute_force_alerts,
    lockout_alerts
):

    correlated_alerts = []

    for brute_alert in brute_force_alerts:

        brute_time = parse_timestamp(
            brute_alert.get(
                "timestamp"
            )
        )

        if brute_time is None:
            continue

        for lockout_alert in lockout_alerts:

            lockout_time = parse_timestamp(
                lockout_alert.get(
                    "timestamp"
                )
            )

            if lockout_time is None:
                continue

            same_user = (
                brute_alert.get("username")
                ==
                lockout_alert.get("username")
            )

            same_ip = (
                brute_alert.get("source_ip")
                ==
                lockout_alert.get("source_ip")
            )

            time_difference = abs(
                (
                    lockout_time
                    - brute_time
                ).total_seconds()
            ) / 60

            if (
                same_user
                and same_ip
                and
                time_difference
                <= BRUTE_FORCE_WINDOW_MINUTES
            ):

                correlated_alerts.append(

                    generate_alert(

                        alert_type=(
                            "Brute Force + "
                            "Account Lockout"
                        ),

                        severity="CRITICAL",

                        username=brute_alert.get(
                            "username"
                        ),

                        source_ip=brute_alert.get(
                            "source_ip"
                        ),

                        workstation=brute_alert.get(
                            "workstation",
                            "N/A"
                        ),

                        attempts=brute_alert.get(
                            "attempts",
                            "N/A"
                        ),

                        timestamp=brute_alert.get(
                            "timestamp",
                            "N/A"
                        ),

                        rule_id="R004",

                        mitre_id="T1110",

                        description=(
                            "Repeated failed authentication "
                            "attempts resulted in an account "
                            "lockout."
                        ),

                        recommended_action=(
                            "Investigate the source immediately, "
                            "verify the affected account, "
                            "and consider blocking the source "
                            "and resetting credentials."
                        )
                    )
                )


    return correlated_alerts


# ============================================================
# ASSIGN ALERT IDs
# ============================================================

def assign_alert_ids(alerts):

    for index, alert in enumerate(
        alerts,
        start=1
    ):

        alert["alert_id"] = (
            f"ALT-{index:04d}"
        )

    return alerts


# ============================================================
# REMOVE DUPLICATE ALERTS
# ============================================================

def remove_duplicate_alerts(alerts):

    unique_alerts = []

    seen = set()

    for alert in alerts:

        key = (
            alert.get("type"),
            alert.get("username"),
            alert.get("source_ip"),
            alert.get("timestamp")
        )

        if key not in seen:

            seen.add(key)

            unique_alerts.append(
                alert
            )

    return unique_alerts


# ============================================================
# INCIDENT CREATION
# ============================================================

def create_incidents(alerts):

    incidents = []

    detected_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    for index, alert in enumerate(
        alerts,
        start=1
    ):

        incident = {

            "incident_id": (
                f"INC-{index:04d}"
            ),

            "incident_type": alert.get(
                "type",
                "Unknown Incident"
            ),

            "priority": alert.get(
                "severity",
                "MEDIUM"
            ),

            "status": "OPEN",

            "source_ip": alert.get(
                "source_ip",
                "N/A"
            ),

            "username": alert.get(
                "username",
                "N/A"
            ),

            "attempts": alert.get(
                "attempts",
                "N/A"
            ),

            "workstation": alert.get(
                "workstation",
                "N/A"
            ),

            "alert_time": alert.get(
                "timestamp",
                "N/A"
            ),

            "detected_time": detected_time,

            "alert_id": alert.get(
                "alert_id",
                "N/A"
            ),

            "rule_id": alert.get(
                "rule_id",
                "N/A"
            ),

            "mitre_attack": alert.get(
                "mitre_attack",
                "N/A"
            ),

            "description": alert.get(
                "description",
                ""
            ),

            "recommended_action": alert.get(
                "recommended_action",
                ""
            )
        }

        incidents.append(
            incident
        )

    return incidents


# ============================================================
# SAVE ALERTS
# ============================================================

def save_alerts(alerts):

    with open(
        "alerts.json",
        "w"
    ) as file:

        json.dump(
            alerts,
            file,
            indent=4
        )


# ============================================================
# SAVE INCIDENTS
# ============================================================

def save_incidents(incidents):

    with open(
        "incidents.json",
        "w"
    ) as file:

        json.dump(
            incidents,
            file,
            indent=4
        )


# ============================================================
# MAIN EXECUTION
# ============================================================

if __name__ == "__main__":

    print(
        "\n========================================"
    )

    print(
        " SOC ALERT & INCIDENT CORRELATION ENGINE"
    )

    print(
        "========================================\n"
    )


    # --------------------------------------------------------
    # STEP 1 — INGEST LOGS
    # --------------------------------------------------------

    print(
        "[1] Ingesting and normalizing logs..."
    )

    all_logs = ingest_and_normalize()

    print(
        f"    Total normalized logs: {len(all_logs)}"
    )


    # --------------------------------------------------------
    # STEP 2 — SORT LOGS
    # --------------------------------------------------------

    all_logs.sort(
        key=lambda log: log.get(
            "timestamp",
            ""
        )
    )


    # --------------------------------------------------------
    # STEP 3 — DETECTION RULES
    # --------------------------------------------------------

    print(
        "\n[2] Running detection rules..."
    )


    brute_force_alerts = detect_failed_logins(
        all_logs
    )

    print(
        f"    Brute Force alerts: "
        f"{len(brute_force_alerts)}"
    )


    lockout_alerts = detect_account_lockout(
        all_logs
    )

    print(
        f"    Account Lockout alerts: "
        f"{len(lockout_alerts)}"
    )


    successful_login_alerts = (
        detect_failed_then_successful(
            all_logs
        )
    )

    print(
        f"    Failed → Successful alerts: "
        f"{len(successful_login_alerts)}"
    )


    # --------------------------------------------------------
    # STEP 4 — CORRELATION
    # --------------------------------------------------------

    print(
        "\n[3] Correlating alerts..."
    )


    correlation_alerts = (
        correlate_bruteforce_lockout(
            brute_force_alerts,
            lockout_alerts
        )
    )

    print(
        f"    Brute Force + Lockout: "
        f"{len(correlation_alerts)}"
    )


    # --------------------------------------------------------
    # STEP 5 — COMBINE ALERTS
    # --------------------------------------------------------

    alerts = (
        brute_force_alerts
        +
        lockout_alerts
        +
        successful_login_alerts
        +
        correlation_alerts
    )


    # --------------------------------------------------------
    # STEP 6 — REMOVE DUPLICATES
    # --------------------------------------------------------

    alerts = remove_duplicate_alerts(
        alerts
    )


    # --------------------------------------------------------
    # STEP 7 — ASSIGN ALERT IDS
    # --------------------------------------------------------

    alerts = assign_alert_ids(
        alerts
    )


    # --------------------------------------------------------
    # STEP 8 — DISPLAY ALERTS
    # --------------------------------------------------------

    print(
        "\n============== ALERTS ==============\n"
    )

    for alert in alerts:

        print(
            f"{alert['alert_id']} | "
            f"{alert['severity']} | "
            f"{alert['type']} | "
            f"{alert['source_ip']}"
        )


    # --------------------------------------------------------
    # STEP 9 — CREATE INCIDENTS
    # --------------------------------------------------------

    print(
        "\n[4] Creating incidents..."
    )

    incidents = create_incidents(
        alerts
    )


    # --------------------------------------------------------
    # STEP 10 — DISPLAY INCIDENTS
    # --------------------------------------------------------

    print(
        "\n============ INCIDENTS ============\n"
    )

    for incident in incidents:

        print(
            f"{incident['incident_id']} | "
            f"{incident['priority']} | "
            f"{incident['incident_type']} | "
            f"{incident['source_ip']}"
        )


    # --------------------------------------------------------
    # STEP 11 — SAVE RESULTS
    # --------------------------------------------------------

    save_alerts(
        alerts
    )

    save_incidents(
        incidents
    )


    print(
        "\n========================================"
    )

    print(
        f"Total Alerts: {len(alerts)}"
    )

    print(
        f"Total Incidents: {len(incidents)}"
    )

    print(
        "Results saved to alerts.json "
        "and incidents.json"
    )

    print(
        "========================================\n"
    )