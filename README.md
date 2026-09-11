# AlertMatrix

## SOC Alert Dashboard with MITRE ATT&CK Mapping

AlertMatrix is a SOC alert monitoring and incident correlation system for Windows/RDP security events. It uses rule-based detection to identify suspicious authentication activity, generate alerts and incidents, and map relevant events to MITRE ATT&CK techniques.

## Technologies Used

- Python
- Streamlit
- JSON
- Windows 10
- Kali Linux
- RDP
- MITRE ATT&CK

## Main Components

- `convert_raw_windows_logs.py` – Converts raw Windows/RDP event data into a structured format.
- `engine.py` – Processes events, applies detection rules, generates alerts and incidents, and performs MITRE ATT&CK mapping.
- `dashboard.py` – Provides the Streamlit-based SOC dashboard.

## Current Detection Scenario

The current implementation focuses on repeated failed Windows/RDP authentication attempts and maps the detected activity to MITRE ATT&CK T1110 – Brute Force.

## Future Enhancements

Additional detection rules, correlation logic, and dashboard capabilities can be added in future versions.
