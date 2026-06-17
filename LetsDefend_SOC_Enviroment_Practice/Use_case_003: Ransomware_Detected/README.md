## SOC145 - Ransomware Detected

### Incident Summary

A critical security alert was triggered after the execution of a suspicious executable file identified as ab.exe on the host MarkPRD (172.16.17.88).

Initial investigation focused on validating the file hash and determining whether the alert represented a legitimate ransomware incident. Threat intelligence analysis revealed that the file hash was identified by 61 out of 70 security vendors as malicious and associated with ransomware activity, specifically the Avaddon ransomware family.

Additional endpoint activity showed the execution of several Windows utilities commonly abused by ransomware operators to disable recovery mechanisms and hinder incident response efforts.

Based on the collected evidence, the alert was classified as a True Positive and escalated for further investigation.

![Alert](./Evidence/Alert_Malware.png)

### Step 1 – Threat Intelligence Validation

The file hash associated with the alert was analyzed using VirusTotal.

**Findings**
- 61/70 security vendors detected the file as malicious.
- Multiple engines classified the sample as ransomware.
- Malware family references included:
- Avaddon
- DelShad

![Alert](./Evidence/Virus_total_analysis.png)

**Conclusion**

- The hash reputation provided strong evidence that the executable represented a legitimate malware threat rather than a false positive.

### Step 2 – Endpoint Investigation

Endpoint telemetry was reviewed to identify suspicious activity following the execution of ab.exe.

The following processes were observed after the ransomware execution:

- wmic.exe
- vssadmin.exe
- wbadmin.exe
- bcdedit.exe

![Alert](./Evidence/Events_captured.png)

These utilities are frequently leveraged by ransomware operators to:

- Delete shadow copies.
- Disable recovery mechanisms.
- Interfere with backup restoration.
- Prepare the environment for file encryption.

### Step 3 – Additional Validation

All legitimate-looking processes observed prior to the alert were validated using VirusTotal and determined to be benign system or user applications, including:

- AcroRd32.exe
- Outlook.exe
- Chrome.exe
- svchost.exe
- explorer.exe
- winlogon.exe

No malicious indicators were identified among those processes.

Indicators of Compromise (IOC)
- File Indicators
- Type |	Value
- Filename	ab.exe
- MD5	0b486fe0503524cfe4726a4022fa6a68
- Host Indicators
- Type |	Value
- Hostname	MarkPRD
- IP Address	172.16.17.88
- Behavioral Indicators
- Process
- wmic.exe
- vssadmin.exe
- wbadmin.exe
- bcdedit.exe

### MITRE ATT&CK Mapping

- Execution

T1204 - User Execution

The ransomware payload was executed on the endpoint.

- Execution

T1059 - Command and Scripting Interpreter

The malware triggered the execution of multiple Windows administrative utilities.

- Impact

T1486 - Data Encrypted for Impact

The malware was identified as ransomware and, according to the scenario documentation, encrypted files on the affected system.

- Defense Evasion

T1490 - Inhibit System Recovery

Observed execution of:

- vssadmin.exe
- wbadmin.exe
- bcdedit.exe

indicates attempts to interfere with recovery and backup mechanisms.

- Discovery

T1047 - Windows Management Instrumentation (WMI)

Execution of:

- wmic.exe

suggests system interaction through WMI functionality.

**Assessment**
Alert Classification: True Positive

Confidence Level: High

**Reasoning**

- File hash detected as malicious by 61/70 security vendors.
- Malware associated with known ransomware family (Avaddon).
- Endpoint activity consistent with ransomware behavior.
- Execution of utilities commonly used to disable recovery capabilities.
- Scenario documentation confirmed successful file encryption.

**Limitations**

Endpoint visibility was limited because detailed telemetry such as:

- Command-line arguments
- Terminal history
- Network activity
- Browser activity

was not available during the investigation.

As a result, the complete attack chain could not be reconstructed from the available evidence.

### Escalation Decision

Escalated to Incident Response Team

The incident was escalated due to confirmed ransomware execution on the endpoint and evidence of actions consistent with recovery inhibition techniques.

Further forensic investigation was recommended to:

- Determine the scope of encrypted data.
- Identify potential lateral movement.
- Assess business impact.
- Support containment and eradication activities.

### Lessons Learned

This investigation highlighted the importance of validating malware alerts through threat intelligence sources and recognizing behavioral indicators associated with ransomware activity.

The case also demonstrated that SOC Analysts often need to make escalation decisions using incomplete telemetry while relying on available evidence to determine risk and severity.
