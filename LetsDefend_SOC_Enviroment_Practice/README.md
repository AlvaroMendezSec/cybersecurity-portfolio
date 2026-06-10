# This is my documented experience in a SOC enviroment with the blue team practice platform "LetsDefend"

The goal of this Lab/Practice is to show my experience dealing with several common types of real simulated SOC incidents like:
- Brute Force attacks attempts
- Ransomware
- Unauthorized Access
- Privilage Scalation
- Phishing attempts
- etc

## Use case #1: Brute force attepmt (Hight severity alert)

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

Multiple authentication attempts originating from the same source IP address.
Attempts were made against five different user accounts.
Initial failures returned the message:
"Username does not exist"
Later attempts returned:
"Username is correct but password is wrong"
The account mane@letsdefend.io experienced the highest number of login attempts.
A successful authentication occurred approximately six minutes after the initial failed attempts.
Threat Intelligence Investigation
Source IP 37.19.221.229 was investigated using available threat intelligence resources.
No known malicious reputation was identified.
Endpoint Investigation

Endpoint activity associated with the user account was reviewed.

### Findings:

Previous legitimate activity was observed before the successful VPN login.
No suspicious process execution or post-authentication activity was identified after the successful VPN login.
No evidence of malware execution, privilege escalation, or lateral movement was observed.
IOC Found
Source IP Address
37.19.221.229
Targeted User Account
mane@letsdefend.io
Timeline
Time	Event
01:45 PM	Multiple VPN login attempts begin from source IP 37.19.221.229
01:45 PM - 01:50 PM	Authentication failures observed against multiple user accounts
01:47 PM	Attempts transition from invalid usernames to valid usernames with incorrect passwords
01:51 PM	Successful VPN authentication for mane@letsdefend.io
Post 01:51 PM	No suspicious activity observed on the endpoint
Classification
True Positive

The investigation identified behavior consistent with password spraying or brute-force activity.

### Supporting evidence:

Multiple user accounts targeted from a single IP address.
Enumeration of valid usernames.
Repeated password failures against valid accounts.
Successful authentication after multiple failed attempts.

Although no malicious post-authentication activity was identified, the authentication pattern matched the detection logic of the brute-force alert and represented a legitimate security concern.

### Recommendation
Reset the password of the affected account.
Review recent activity associated with the account.
Enable Multi-Factor Authentication (MFA) if not already implemented.
Monitor for additional authentication attempts from the source IP address.
Review VPN access logs for similar activity targeting other users.

### Escalated for further review.

Reason:
A successful VPN authentication occurred after multiple failed login attempts against several user accounts. Additional review by a senior analyst is recommended to determine whether account compromise occurred and whether containment actions are necessary.
