# SOC164 - Suspicious Mshta,exe Behavior

## Executive Summary

A high-severity alert was triggered after mshta.exe, a legitimate Windows binary frequently abused by threat actors, executed a suspicious HTA file located on the user's desktop.

Investigation revealed that the HTA file spawned PowerShell and executed an obfuscated script that attempted to retrieve additional content from an external server (193.142.58.23) using PowerShell's WebClient functionality. The downloaded content was intended to be executed in memory using Invoke-Expression (IEX).

Although the remote resource returned an HTTP 404 response at the time of investigation, the observed behavior matches common malware delivery techniques and Living-Off-The-Land attack patterns.

The alert was classified as a True Positive and escalated for incident response.

## Alert Details

| Field          | Value                                                          |
| -------------- | -------------------------------------------------------------- |
| Related Binary | mshta.exe                                                      |
| HTA File       | Ps1.hta                                                        |
| HTA MD5        | 6685c433705f558c553578923f4db0e5a                              |
| Command Line   | C:/Windows/System32/mshta.exe C:/Users/Roberto/Desktop/Ps1.hta |
| Reputation     | Low Reputation HTA                                             |

![Alert_LOLBin](../Evidence/Alert_LOLBin.png)

## Investigation Process

### Step 1 – Validate Alert Context

The alert indicated that a low-reputation HTA file was executed through Microsoft's legitimate utility: mshta.exe Ps1.hta

Because HTA files can execute scripts with the user's privileges and are frequently abused by malware, the activity warranted further investigation.

### Step 2 – Hash Reputation Analysis

The HTA file hash was investigated.

| Indicator      | Result                            |
| -------------- | --------------------------------- |
| MD5            | 6685c433705f558c553578923f4db0e5a |
| Detection Name | Trojan.Valyria/Powershell         |
| Verdict        | Suspicious                        |

![Trojan](../Evidence/Trojan_Valyria.png)

- Although reputation alone is not sufficient for classification, it supported the need for deeper analysis.

### Step 3 – Process Analysis

Process telemetry revealed that:

mshta.exe
└── powershell.exe

The spawned PowerShell process executed an obfuscated command.

### Step 4 – PowerShell Analysis

Decoded behavior showed the script:

- Created a WebClient object.
- Connected to an external IP address.
- Downloaded remote content.
- Attempted to execute it in memory using IEX.

![Trojan](../Evidence/Command_executed.png)

**Relevant fragments:**

- New-Object Net.WebClient
- http://193.142.58.23/Server.txt
- IEX

This behavior is consistent with a PowerShell download cradle commonly used during malware staging.

### Step 5 – Network Analysis

Firewall logs showed outbound communication attempts from the affected endpoint.

| Source IP    | Destination IP | Port | Resource    |
| ------------ | -------------- | ---- | ----------- |
| 172.16.17.38 | 193.142.58.23  | 80   | /Server.txt |

![Trojan](../Evidence/Net_Log.png)

Observed request: http://193.142.58.23/Server.txt

The server returned an HTTP 404 response during investigation, but the attempted retrieval itself is suspicious and aligns with malware delivery behavior.

### Findings

#### Evidence of LOLBin Abuse**
- Legitimate Windows binary: mshta.exe
- Used to execute: Ps1.hta

#### Evidence of PowerShell Abuse
- PowerShell was launched from the HTA file and attempted to download remote content.

#### Evidence of Remote Payload Retrieval

- Connection observed: 193.142.58.23
- Remote resource: Server.txt

**imagen**

#### Evidence of In-Memory Execution

PowerShell attempted to execute downloaded content via: IEX

- A common technique used to avoid writing malware to disk.

### MITRE ATT&CK Mapping

| Tactic              | Technique                            | ID        |
| ------------------- | ------------------------------------ | --------- |
| Execution           | Signed Binary Proxy Execution: Mshta | T1218.005 |
| Execution           | PowerShell                           | T1059.001 |
| Command and Control | Ingress Tool Transfer                | T1105     |
| Defense Evasion     | Obfuscated Files or Information      | T1027     |
| Execution           | Command and Scripting Interpreter    | T1059     |

### Indicators of Compromise (IoCs)

| Type       | Value                                                              |
| ---------- | ------------------------------------------------------------------ |
| MD5        | 6685c433705f558c553578923f4db0e5a                                  |
| File       | Ps1.hta                                                            |
| Binary     | mshta.exe                                                          |
| Process    | powershell.exe                                                     |
| URL        | [http://193.142.58.23/Server.txt](http://193.142.58.23/Server.txt) |
| IP Address | 193.142.58.23                                                      |

### Timeline

| Time     | Event                                             |
| -------- | ------------------------------------------------- |
| 10:29 AM | mshta.exe executed Ps1.hta                        |
| 10:29 AM | HTA spawned PowerShell                            |
| 10:29 AM | PowerShell decoded obfuscated content             |
| 10:29 AM | WebClient attempted connection to 193.142.58.23   |
| 10:29 AM | Request sent for Server.txt                       |
| 10:29 AM | Downloaded content intended for execution via IEX |
| 10:29 AM | Alert SOC164 triggered                            |

### Analyst Conclusion

The investigation confirmed malicious use of the legitimate Windows utility mshta.exe to execute a suspicious HTA file. The HTA launched an obfuscated PowerShell command that attempted to retrieve and execute remote content from an external server.

The observed behavior matches common malware staging techniques and Living-Off-The-Land attack patterns frequently used to evade traditional security controls.

Final Verdict: True Positive

Escalation: Incident Response Team

Risk Assessment: High

