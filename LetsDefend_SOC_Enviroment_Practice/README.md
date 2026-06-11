# This is my documented experience in a SOC enviroment with the blue team practice platform "LetsDefend"

The goal of this Lab/Practice is to show my experience dealing with several common types of real simulated SOC incidents like:
- Brute Force attacks attempts
- Ransomware
- Unauthorized Access
- Privilage Scalation
- Phishing attempts
- etc

## Use case-001: Brute force attepmt (Hight severity alert)

### Incident Summary

A high-severity alert (SOC210 - Possible Brute Force Detected on VPN) was generated after multiple failed VPN authentication attempts were observed from a single source IP address, followed by a successful login. The alert indicated potential brute-force or password-spraying activity targeting VPN access.

### Evidence Analyzed
Alert Information
Alert Name: SOC210 - Possible Brute Force Detected on VPN
Severity: High
Source IP: 37.19.221.229
Destination: VPN Gateway (vpn-letsdefend.io)
Successful User Authentication: mane@letsdefend.io
Authentication Logs

## Investigation of VPN authentication logs revealed:

- Multiple authentication attempts originating from the same source IP address.
- Attempts were made by trying multiple usernames (user enumeration) until one of them match as a valid username
- Initial failures returned the message: "Username does not exist"
- Later attempts returned: "Username is correct but password is wrong"
- Then account mane@letsdefend.io experienced highest number of login attempts.
- A successful authentication occurred approximately six minutes after the initial failed attempts.
- Threat Intelligence Investigation:
  - Source IP 37.19.221.229 was investigated using available threat intelligence resources.
  - No known malicious reputation was identified.
 
### MITRE-ATT&CK:

  - T1110 - Brute Force
  - T1110.003 - Password Sprying

### Endpoint Investigation

Endpoint activity associated with the user account was reviewed.

#### Findings:

- Previous legitimate activity was observed before the successful VPN login.
- No suspicious process execution or post-authentication activity was identified after the successful VPN login.
- No evidence of malware execution, privilege escalation, or lateral movement was observed.
- IOC Found:
  - Source IP Address: 37.19.221.229

- Targeted User Account: mane@letsdefend.io
- Timeline:
- 01:43 PM	Multiple VPN login attempts begin from source IP 37.19.221.229
- 01:45 PM - 01:43 PM	Authentication failures observed against trying multiple user accounts
- 01:47 - 01:50PM	Attempts transition from invalid usernames to valid username with incorrect passwords
- 01:51 PM	Successful VPN authentication for mane@letsdefend.io
- Post 01:51 PM	No suspicious activity observed on the endpoint
- Classification: True Positive


The investigation identified behavior consistent with password spraying or brute-force activity.

### Supporting evidence:

- Trying different usernames and targeted from a single IP address.
- Username "mane@letsdefend.io" was correct.
- Repeated password failures against mane@letsdefend.io
- Successful authentication after multiple password failed attempts.

Although no malicious post-authentication activity was identified, the authentication pattern matched the detection logic of the brute-force alert and represented a legitimate security concern.

### Recommendation
- Reset loggin credentials of the affected account.
- Review recent activity associated with the account.
- Enable Multi-Factor Authentication (MFA) if not already implemented.
-Monitor for additional authentication attempts from the source IP address.
- Review VPN access logs for similar activity targeting other users.

### Escalated for further review.

Reason:
A successful VPN authentication occurred after multiple failed login attempts against account "mane@letsdefend.io". Additional review by a senior analyst is recommended to determine whether account compromise occurred and whether containment actions are necessary.

## Use case-002 RCE Detected in splunk enterprise (Hight severity alert)

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
