SOC239 - Remote Code Execution Detected in Splunk Enterprise

### Incident Summary

A high-severity alert was triggered after the detection of a malicious XSLT file upload targeting a Splunk Enterprise server. Initial investigation revealed successful authentication to the Splunk web interface using the administrative account, followed by the upload of a malicious XSL file designed to create a reverse shell script on the target system.

Subsequent endpoint telemetry confirmed command execution on the host and the creation of a new local user account, indicating successful compromise and persistence establishment.

### Evidence Analyzed
- Alert Information
  - Alert Name: SOC239 - Remote Code Execution Detected in Splunk Enterprise
- Severity: High
- Event Type: Unauthorized Access
- Source IP: 180.101.88.240
- Destination IP: 172.16.20.13
- HTTP Method: POST
- Affected System: Splunk Enterprise Server
- Authentication Activity

A successful authentication attempt was observed shortly before the malicious upload activity:

- Username: admin
- Request: POST /account/login
- Response Code: 200 OK
- Malicious Files

The uploaded archive contained:

- shell.xsl
- shell.sh


The XSLT file was configured to create the shell.sh script inside:

/opt/splunk/bin/scripts/

The generated script was intended to establish a reverse shell connection to the attacker's host.

Endpoint Activity

The following commands were executed on the compromised server:

- id
- whoami
- ls
- cat

Observed processes:

Parent Process: sshd
Shell: bash

Additional persistence-related activity was identified:

- useradd -m analyst
- passwd analyst

These commands created a new local user account and assigned credentials.

### IOC Found
- Network Indicators
- Type	Value
- Source IP	180.101.88.240
- Reverse Shell Destination	180.101.88.240:1923
- Login Endpoint	/account/login
- File Indicators
- Type	Value
- XSL File	shell.xsl
- Shell Script	shell.sh
- User Indicators
- Administrative Account	admin
- Created Account	analyst
- Timeline: 12:23:56 PM


Successful authentication attempt observed:

- POST /account/login
- Username: admin
- password: SPLUNK-i-04673a41b8017af54
- Response: 200
- 12:24 PM

Malicious XSLT file uploaded to Splunk Enterprise.

- 12:24:28 PM

- Command execution detected:

id
12:24:33 PM

- Command execution detected:

whoami
12:24:44 PM

Local account creation detected:

12:24:48 PM: useradd -m analyst


Password assignment detected:

- 12:24:55 PM: passwd analyst


Directory enumeration activity detected:

- ls

### MITRE ATT&CK Mapping

#### Initial Access

  - T1190 - Exploit Public-Facing Application

    - The attacker abused a vulnerable Splunk feature by uploading a malicious XSLT file designed to achieve code execution.

- Execution

- T1059.004 - Command and Scripting Interpreter: Unix Shell

- Commands were executed through a Linux shell environment:

- id
- whoami
- ls
- Discovery

#### T1033 - System Owner/User Discovery

The attacker executed:

- whoami: to determine the current user context.

#### Discovery

- T1087 - Account Discovery

The attacker executed:

- id: to enumerate account and privilege information.

#### Persistence

- T1136.001 - Create Account: Local Account

- A new local user account was created: useradd -m analyst

followed by: passwd analyst to establish persistence.

#### Command and Control

T1071 - Application Layer Protocol

The reverse shell payload attempted to establish outbound communications over TCP.

### Classification:

- True Positive: Evidence confirms successful compromise of the Splunk Enterprise server through authenticated exploitation, command execution, and persistence establishment.

### Recommendation

- Immediately isolate the affected Splunk server.
- Disable and investigate the newly created user account.
- Reset credentials associated with the administrative account.
- Review Splunk configuration and patch vulnerable components.
- Search for additional indicators of compromise across the environment.
- Review outbound network connections to identify potential command-and-control communications.
- Conduct forensic analysis to determine the full scope of attacker activity.
- Escalation Decision

### Escalated to Incident Response Team

The incident was escalated due to confirmed command execution and persistence establishment on a production server. Additional forensic investigation is required to determine the extent of compromise, identify potential lateral movement, and perform containment and eradication activities.
