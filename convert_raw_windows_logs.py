import json
import re

# Read raw JSON
with open("rdpFailedLogins.json", "r", encoding="utf-16") as f:
    raw_logs = json.load(f)

# If only one event exists, make it a list
if isinstance(raw_logs, dict):
    raw_logs = [raw_logs]


def extract_field(message, field):
    pattern = rf"{re.escape(field)}:\s*(.*)"
    match = re.search(pattern, message)
    if match:
        return match.group(1).strip()
    return "N/A"


clean_logs = []

for log in raw_logs:

    message = log.get("Message", "")

    clean_log = {
        "TimeCreated": str(log.get("TimeCreated", "")),
        "EventID": log.get("Id"),
        "ProviderName": log.get("ProviderName"),

        "TargetUserName": re.search(
         r"Account For Which Logon Failed:\s+Security ID:\s+.*?\s+Account Name:\s+([^\r\n]+)",
         message,
         re.DOTALL
         ).group(1).strip() if re.search(
         r"Account For Which Logon Failed:\s+Security ID:\s+.*?\s+Account Name:\s+([^\r\n]+)",
         message,
         re.DOTALL
         ) else "N/A",
        "TargetDomain": extract_field(message, "Account Domain"),
        "LogonType": extract_field(message, "Logon Type"),
        "WorkstationName": extract_field(message, "Workstation Name"),
        "IpAddress": extract_field(message, "Source Network Address"),
        "SourcePort": extract_field(message, "Source Port"),
        "Status": extract_field(message, "Status"),
        "SubStatus": extract_field(message, "Sub Status"),
        "AuthenticationPackage": extract_field(message, "Authentication Package"),
        "ProcessName": extract_field(message, "Process Name")
    }

    clean_logs.append(clean_log)

# Save cleaned JSON
with open("windows_logs.json", "w", encoding="utf-8") as f:
    json.dump(clean_logs, f, indent=4)

print("windows_logs.json created successfully.")