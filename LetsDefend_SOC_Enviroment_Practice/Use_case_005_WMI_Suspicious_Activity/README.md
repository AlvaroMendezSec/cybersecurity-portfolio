# SOC134 – Suspicious WMI Activity (Critical Alert)

## Incident Overview

- Date: March 7, 2021
- Alert ID: SOC134
- Severity: Critical
- Category: Malware / Suspicious WMI Activity
- Hostname: Desktop-Anderson
- IP Address: 172.16.17.54
- Analyst Verdict: True Positive

![AlertRAT](./Evidence/AlertRAT.png)

## Executive Summary

A critical alert was generated after the detection of suspicious Windows Management Instrumentation (WMI) activity on the endpoint Desktop-Anderson. Initial investigation identified the execution of a batch script leveraging Impacket's wmiexec.py, a tool commonly used by administrators, penetration testers, and threat actors for remote command execution.

Further analysis uncovered a suspicious executable named services.exe located on the user's Desktop rather than within legitimate Windows system directories. String analysis suggested the binary was a Remote Access Trojan (RAT) developed in Go.

Additional evidence revealed system reconnaissance activity, outbound communications to an external host over port 4444, and the transmission of encoded data containing host information and credentials. Based on the collected evidence, the alert was classified as a True Positive and escalated for further malware analysis and incident response.

## Investigation Process

### Initial Alert Analysis

The alert identified a file named: exec.bat

Hash: 50459310eded4c520ab5c9e3626a9300

Upon inspection, the batch file contained: python wmiexec.py LetsDefend/Administrator@127.0.0.1

This command launches wmiexec.py, a component of the Impacket toolkit that enables remote command execution through Windows Management Instrumentation (WMI).

Although the file hash showed only 1 detection out of 61 security vendors in VirusTotal, the behavior itself warranted further investigation.

### Endpoint Investigation

Process telemetry revealed the existence of a suspicious executable: C:\Users\Anderson\Desktop\services.exe

Several characteristics immediately raised suspicion:

- Located outside legitimate Windows directories
- Name closely resembles legitimate Windows services
- Not a standard Windows binary
- Contained suspicious embedded strings
- Extracted Strings:

| String         | Observation                      |
| -------------- | -------------------------------- |
| go.buildid     | Indicates Go compilation         |
| rat.New        | Possible RAT functionality       |
| agent_time     | Agent-related functionality      |
| agent_platform | Endpoint information collection  |
| ports          | Network communication capability |
| pid            | Process tracking functionality   |


The presence of rat.New strongly suggested that the binary was designed as a Remote Access Trojan.

### Host Activity Analysis

Historical terminal activity showed multiple reconnaissance commands consistent with attacker enumeration behavior.

**Observed Commands**

| Timestamp         | Command           |
| ----------------- | ----------------- |
| 18-Dec-2020 09:13 | ipconfig          |
| 18-Dec-2020 09:14 | dir               |
| 19-Dec-2020 09:15 | hostname          |
| 19-Dec-2020 09:16 | net user          |
| 19-Dec-2020 09:17 | whoami            |
| 19-Dec-2020 11:18 | tasklist          |
| 19-Dec-2020 11:20 | net user anderson |
| 19-Dec-2020 11:21 | ping 172.16.20.1  |


These commands are frequently observed during the reconnaissance phase of an intrusion.

### Network Analysis

Log management data revealed outbound communications from the host to an external IP address.

Suspicious Connections

| Source       | Destination   | Port |
| ------------ | ------------- | ---- |
| 172.16.17.54 | 161.35.41.241 | 4444 |


The destination IP belongs to DigitalOcean LLC.

Although VirusTotal showed only limited detections (2/91 vendors), infrastructure hosted on cloud providers is frequently abused by threat actors.

### Encoded Data Analysis

Several outbound communications contained Base64-encoded content.

Decoded Data
- Host Identification
- hostname:DESKTOP-ANDERSON
- Credential Data
- Passlist:
  - Anderson:ander12son!
  - Administrator:mys3r3tP@ss!


The decoded content indicates the transmission of:

- Host identification data
- User account information
- Credentials

This behavior is consistent with credential harvesting and possible exfiltration activity.

Timeline of Events

| Event                        | Description                                             |
| ---------------------------- | ------------------------------------------------------- |
| Initial Activity             | WMI execution initiated via wmiexec.py                  |
| Reconnaissance               | ipconfig, hostname, whoami, net user, tasklist          |
| Suspicious Binary Identified | services.exe discovered on Desktop                      |
| Binary Analysis              | Go-based RAT indicators observed                        |
| Network Activity             | Communication to 161.35.41.241:4444                     |
| Data Transmission            | Base64-encoded host and credential information observed |
| Analyst Verdict              | True Positive                                           |
| Escalation                   | Tier 2 Incident Response                                |


### Indicators of Compromise (IoCs)

| Type | Value                            |
| ---- | -------------------------------- |
| File | exec.bat                         |
| File | services.exe                     |
| MD5  | 50459310eded4c520ab5c9e3626a9300 |


### Network

| Type       | Value         |
| ---------- | ------------- |
| IP Address | 161.35.41.241 |
| Port       | 4444          |


### Commands

| Command    |
| ---------- |
| wmiexec.py |
| hostname   |
| whoami     |
| net user   |
| tasklist   |
| ipconfig   |

### MITRE ATT&CK

| Technique ID | Technique                                |
| ------------ | ---------------------------------------- |
| T1047        | Windows Management Instrumentation       |
| T1036        | Masquerading                             |
| T1033        | System Owner/User Discovery              |
| T1087        | Account Discovery                        |
| T1057        | Process Discovery                        |
| T1016        | System Network Configuration Discovery   |
| T1041        | Exfiltration Over C2 Channel (Suspected) |


## Analyst Assessment

While reputation-based intelligence alone was insufficient to classify the activity as malicious, correlation of multiple evidence sources revealed a strong malicious pattern:

- WMI-based command execution
- Suspicious executable masquerading as a legitimate service
- RAT-related indicators
- Host reconnaissance activity
- External communications over port 4444
- Transmission of encoded credentials

The combination of these findings supports the conclusion that the endpoint was involved in malicious activity consistent with remote access trojan behavior and potential credential theft.

## Final Verdict

Classification: True Positive

Reason: Evidence of WMI-based execution, suspicious RAT-like binary activity, system reconnaissance, external communications, and transmission of credential data.

Recommended Action: Escalate to Incident Response team for malware analysis, scope determination, containment, and credential compromise assessment.

