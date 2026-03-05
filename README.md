# Brute-Force-detection
Splunk-based brute force attack detection with custom SPL queries, alerts, and MITRE ATT&amp;CK T1110 mapping

# Brute Force Attack Detection & Alerting

## Objective
  Simulated brute force login attacks against a Windows endpoint in a home lab environment,  then built custom Splunk SIEM detection rules to catch them. Configured real-time alerts with tuned thresholds to minimize false positives and documented a detected attack in a professional incident report.

## Lab Architecture
| Component              | Details                                               |
|------------------------|-------------------------------------------------------|
| **SIEM Platform**      | Splunk Enterprise (Ubuntu 24.04 VM)                   |
| **Target Endpoint**    | Windows VM — ComputerName: WindowsEndpoint            |
| **Attack Simulation**  | Bash script generating sequential failed login events |
| **Network**            | VirtualBox NAT Network                                |
| **Log Source**         | Windows Security Event Log (WinEventLog:Security)     |

## Attack Simulation
  A Bash script was used to simulate a brute force attack by generating 53 rapid failed login attempts (Windows EventCode 4625) against sequential fake user accounts (fakeuser1 through fakeuser25+) on the Windows endpoint over approximately 53 seconds.

# Brute force simulation script
for i in $(seq 1 25); do
  net use \\WindowsEndpoint\IPC$ /user:fakeuser$i wrongpassword 2>&1
done

## Detection Rules (SPL Queries)

### Query 1 — Basic Brute Force Detection (Windows)
index=main sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, ComputerName
| where count > 5

### Query 2 — Time-Bucketed Detection (Primary Alert Query)
index=main sourcetype="WinEventLog:Security" EventCode=4625
| bucket _time span=10m
| stats count by _time, Account_Name, ComputerName
| where count > 5
| sort - count

### Query 3 — Advanced Correlation (Failed then Succeeded)
index=main sourcetype="WinEventLog:Security" EventCode=4625
| transaction Account_Name maxspan=10m
| where eventcount > 5
| table Account_Name, eventcount, duration, ComputerName

### Query 4 — Combined Failed + Successful Login Correlation
index=main sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| stats count by EventCode, Account_Name, ComputerName
| sort - count

## Alert Configuration

| Setting            | Value                   | Reason                                   |
|--------------------|-------------------------|------------------------------------------|
| **Alert Type**     | Scheduled               | Runs on a timer automatically            |
| **Schedule**       | Every 10 minutes        | Matches the 10-minute search window      |
| **Time Range**     | Last 10 minutes         | No gaps or overlaps in coverage          |
| **Trigger When**   | Number of results > 0   | SPL already filters to suspicious IPs    |
| **Severity**       | High                    | Failed logins at volume = active threat  |
| **Expires After**  | 24 hours                | Standard alert retention                 |

## Tuning Decisions

| Threshold Tested | Result                                                      | Decision     |
|------------------|-------------------------------------------------------------|--------------|
| `count > 2`      | Too many false positives — normal typos triggered alert     | Rejected     |
| `count > 10`     | Missed the attack burst — threshold too high                | Rejected     |
| `count > 5`      | Caught all 53 simulated events, filtered normal user errors | **Selected** |

**Rationale:** 
  A legitimate user rarely fails to log in more than 2–3 times in 10 minutes. A threshold of 5 provides a buffer above normal human error while reliably catching automated brute force tools.

## Results

| Metric                        | Value                                 |
|-------------------------------|---------------------------------------|
| Total Failed Logins Detected  | **53 events** (EventCode 4625)        |
| Target System                 | WindowsEndpoint                       |
| Accounts Targeted             | fakeuser1 – fakeuser25+ (sequential)  |
| Attack Duration               | ~53 seconds (19:33:04 – 19:33:57)     |
| Successful Logins             | **0** — Attack failed                 |
| Alert Triggered               | ✅ Yes — within one 10-minute window  |


## Key SPL Fields (Windows Security Logs)

| Field            | Description                                       |
|------------------|---------------------------------------------------|
| `EventCode=4625` | Failed login attempt                              |
| `EventCode=4624` | Successful login                                  |
| `Account_Name`   | Username that was targeted                        |
| `ComputerName`   | Endpoint where the event occurred                 |
| `IpAddress`      | Source IP of the login attempt                    |
| `LogonType`      | Method used (2=interactive, 3=network, 10=remote) |

## MITRE ATT&CK Mapping

| Tactic            | Technique         | ID        |
|-------------------|-------------------|-----------|
| Credential Access | Brute Force       | T1110     |
| Credential Access | Password Guessing | T1110.001 |
| Discovery         | Account Discovery | T1087     |

## Skills Demonstrated

- Splunk SIEM alert creation and scheduling
- SPL query writing for threat detection
- Brute force attack simulation
- Alert threshold tuning to reduce false positives
- Incident documentation and reporting
- MITRE ATT&CK framework mapping

[brute_force_tuning_notes.md](https://github.com/user-attachments/files/25754554/brute_force_tuning_notes.md)
[brute_force_sim.sh](https://github.com/user-attachments/files/25754553/brute_force_sim.sh)
[incident_report_brute_force.md](https://github.com/user-attachments/files/25754559/incident_report_brute_force.md)
[mitre_mapping,md](https://github.com/user-attachments/files/25754563/mitre_mapping.md)
[queries.md](https://github.com/user-attachments/files/25754567/queries.md)
[# Brute Force Simulation - Windows.txt](https://github.com/user-attachments/files/25754693/Brute.Force.Simulation.-.Windows.txt)
<img width="1274" height="790" alt="Dashboard" src="https://github.com/user-attachments/assets/ad31147b-3217-473c-ab08-cf765d4f4c25" />
<img width="1284" height="824" alt="Dashboard 1" src="https://github.com/user-attachments/assets/19cb6424-60ca-4b40-9373-a8fb8e713195" />


