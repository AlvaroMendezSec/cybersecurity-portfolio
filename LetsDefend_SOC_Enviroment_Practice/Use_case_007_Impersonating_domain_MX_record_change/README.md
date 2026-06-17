# SOC Case Study #5 – Impersonating Domain MX Record Change Detected

## Incident Summary

A security alert was generated after detecting a modification to the MX record of a domain impersonating the legitimate LetsDefend domain.

The suspicious domain letsdefwnd[.]io closely resembles the legitimate LetsDefend domain and was configured with a new mail exchange (MX) record: mail.mailerhost.net

MX record changes on impersonating domains are commonly associated with phishing infrastructure preparation, allowing threat actors to send or receive emails that appear legitimate.

Although no malware, phishing page, or malicious payload was directly observed during the investigation, the combination of domain impersonation and MX record configuration represents a credible phishing risk.

The alert was classified as a True Positive and escalated for further monitoring and threat intelligence analysis.

Alert Details

| Field             | Value                                                   |
| ----------------- | ------------------------------------------------------- |
| Alert Name        | SOC326 - Impersonating Domain MX Record Change Detected |
| Event ID          | 304                                                     |
| Severity          | Medium                                                  |
| Category          | Threat Intelligence                                     |
| Date              | September 17, 2024                                      |
| Source Email      | [no-reply@cti-report.io](mailto:no-reply@cti-report.io) |
| Destination Email | [soc@letsdefend.io](mailto:soc@letsdefend.io)           |
| Suspicious Domain | letsdefwnd[.]io                                         |
| MX Record         | mail.mailerhost.net                                     |
| Device Action     | Allowed                                                 |

## Step 1 – Analyze Alert Context

The alert indicated that an impersonating domain had changed its MX record.

- Legitimate Domain
- letsdefend.io
- Suspicious Domain
- letsdefwnd.io

The attacker replaced the letter:  m → w creating a visually similar domain likely intended to deceive users.

This technique is known as:

- Typosquatting
- Domain Impersonation
- Brand Abuse

## Step 2 – Review Domain Intelligence

The email security platform provided the following information:

| Field           | Value                    |
| --------------- | ------------------------ |
| Registrar       | Sav.com, LLC             |
| Registrant      | Privacy Protected        |
| Creation Date   | Sep 22, 2023             |
| Status          | clientTransferProhibited |
| Risk Level      | High                     |
| Phishing Status | Action Waiting           |
| State           | Not Parked               |


- The domain was active and operational rather than parked.

## Step 3 – Analyze DNS Infrastructure

| Type | Value              |
| ---- | ------------------ |
| NS   | ns1.giantpanda.com |
| NS   | ns2.giantpanda.com |

| Type | Value               |
| ---- | ------------------- |
| MX   | mail.mailerhost.net |


- The newly configured MX record indicates the infrastructure is capable of sending and/or receiving email.

- This significantly increases phishing risk because attackers can distribute emails appearing to originate from the impersonating domain.

## Step 4 – Review Associated IP Addresses

The platform identified multiple IP addresses associated with the suspicious domain.

| IP Address      |
| --------------- |
| 72.14.178.174   |
| 45.33.30.197    |
| 72.14.185.43    |
| 173.255.194.134 |
| 45.79.19.196    |
| 45.56.79.23     |
| 96.126.123.244  |
| 45.33.20.235    |
| 45.33.18.44     |
| 45.33.2.79      |
| 198.58.118.167  |
| 45.33.23.183    |


- No significant detections were observed in VirusTotal or LetsDefend Threat Intelligence at the time of investigation.

## Step 5 – Threat Intelligence Verification

The following checks were performed:

| Source                         | Result                                |
| ------------------------------ | ------------------------------------- |
| VirusTotal Domain Search       | No significant detections             |
| LetsDefend Threat Intelligence | No known malicious reports            |
| Domain Reputation Review       | No confirmed malicious classification |


Although no direct malicious activity was identified, domain impersonation combined with MX record configuration remains highly suspicious.

## Step 6 – Assess Potential Threat

The domain exhibited several phishing indicators:

| Indicator                      | Present |
| ------------------------------ | ------- |
| Typosquatting                  | ✅       |
| Brand Impersonation            | ✅       |
| Active MX Record               | ✅       |
| Privacy Protected Registration | ✅       |
| Phishing Monitoring Alert      | ✅       |
| Malware Hosted                 | ❌       |
| Confirmed Credential Theft     | ❌       |


Based on the available evidence, the infrastructure appears prepared for phishing operations.

## MITRE ATT&CK Mapping

| Technique ID | Technique                           |
| ------------ | ----------------------------------- |
| T1583.001    | Acquire Infrastructure: Domains     |
| T1584.001    | Compromise Infrastructure: Domains  |
| T1585.001    | Establish Accounts: Email Accounts  |
| T1566        | Phishing                            |
| T1586.002    | Compromise Accounts: Email Accounts |

## Indicators of Compromise (IOCs)

### Domains

| Indicator             |
| --------------------- |
| letsdefwnd[.]io       |
| mail.mailerhost[.]net |

### Email Address
| Indicator                                               |
| ------------------------------------------------------- |
| [no-reply@cti-report.io](mailto:no-reply@cti-report.io) |
| [soc@letsdefend.io](mailto:soc@letsdefend.io)           |


## Investigation Timeline

| Time                  | Activity                                                      |
| --------------------- | ------------------------------------------------------------- |
| Alert Generated       | MX record change detected on impersonating domain             |
| Initial Review        | Domain identified as typosquatting attempt against LetsDefend |
| DNS Analysis          | MX record configured as mail.mailerhost.net                   |
| Reputation Check      | VirusTotal and TI searches performed                          |
| Infrastructure Review | Multiple associated IP addresses identified                   |
| Risk Assessment       | Domain capable of supporting phishing campaigns               |
| Final Classification  | True Positive                                                 |
| Escalation            | Recommended monitoring and blocking                           |


## Analyst Conclusion

The investigation confirmed that the domain letsdefwnd[.]io was intentionally registered to imitate the legitimate LetsDefend domain. The presence of an active MX record indicates preparation for email-based phishing operations.

Although no phishing emails, credential harvesting pages, or malware payloads were directly observed during the investigation, the combination of domain impersonation, active mail infrastructure, and brand abuse indicators provides sufficient evidence to classify the alert as a True Positive.

The domain should be monitored continuously and blocked within organizational security controls to reduce the risk of phishing and brand impersonation attacks.
