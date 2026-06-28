# SOC127 – SQL Injection Attempt Detected

## Executive Summary

This investigation analyzed a **high-severity SQL Injection attack** targeting a public-facing web application.

The investigation began after multiple HTTP requests containing SQL injection payloads triggered a Web Attack alert. By correlating **web server logs**, **HTTP responses**, and attacker behavior, I confirmed that the attacker used the automated exploitation framework **sqlmap** to perform multiple SQL injection techniques, including **Boolean-based**, **Error-based**, and **UNION-based** injection, followed by **database enumeration** and **operating system command execution attempts**.

Although no evidence of successful command execution, data exfiltration, or server compromise was identified, the application processed every malicious request with **HTTP 200 OK**, demonstrating that the SQL payloads successfully reached the application layer.

Based on the available evidence, the incident was classified as a **True Positive SQL Injection attack** requiring immediate remediation of the vulnerable application.

---

# Alert Overview

| Field | Value |
|---------|--------|
| Severity | High |
| Category | Web Attack |
| Rule | SOC127 – SQL Injection Detected |
| Detection Date | March 07, 2024 |
| Source IP | 118.194.247.28 |
| Target Host | WebServer1000 |
| Target IP | 172.16.20.12 |
| Tool Identified | sqlmap 1.7.2 |
| Detection Source | Web Server Logs |
| Classification | True Positive |

---

# Investigation Timeline

| Time | Activity |
|------|----------|
| 12:51 | SQL Injection attack begins |
| 12:53 | Automated SQL payloads detected |
| 12:53 | Boolean-based SQL Injection identified |
| 12:53 | Error-based SQL Injection identified |
| 12:53 | UNION-based SQL Injection identified |
| 12:53 | Database enumeration attempts observed |
| 12:53 | Operating system command execution attempts detected |
| 12:54 | Investigation completed and incident escalated |

---

# Technical Investigation

## Step 1 – Initial Alert Validation

The investigation began after a Web Attack alert identified multiple HTTP requests containing SQL syntax targeting the public web application.

The requests immediately exhibited several characteristics commonly associated with SQL Injection attacks:

- UNION SELECT statements
- EXTRACTVALUE function abuse
- CASE WHEN conditional logic
- CAST and CHR obfuscation
- References to information_schema
- Automated payload generation

Rather than a single malformed request, the application received a sequence of carefully crafted payloads designed to validate and exploit SQL Injection vulnerabilities.

### Initial Assessment

The alert presented a high probability of malicious activity.

However, additional investigation was required to determine:

- whether the requests were manually generated or automated;
- how far the attacker progressed;
- whether the application interacted with the backend database;
- whether post-exploitation activity occurred.

---

## Step 2 – Web Log Analysis

The next phase focused on reviewing the web server logs associated with the source IP address.

Multiple HTTP GET requests were identified originating from:

```
118.194.247.28
```

One of the most significant observations was the HTTP User-Agent:

```
sqlmap/1.7.2#stable
```

This immediately identified the framework used during the attack.

**sqlmap** is one of the most widely used automated SQL Injection exploitation tools, capable of:

- discovering SQL Injection vulnerabilities;
- fingerprinting database engines;
- enumerating databases;
- extracting sensitive information;
- attempting operating system command execution.

### Web Log Evidence

| Field | Value |
|------|------|
| Source IP | 118.194.247.28 |
| Method | GET |
| Target URI | `/index.php?id=` |
| User-Agent | `sqlmap/1.7.2#stable` |

### Analyst Assessment

The web logs confirmed that the activity was not random or accidental.

Instead, the requests originated from an automated exploitation framework specifically designed to identify and exploit SQL Injection vulnerabilities.

---

## Step 3 – SQL Injection Validation

The attacker initially focused on determining whether SQL Injection was possible.

Multiple payloads demonstrated different validation techniques commonly employed by sqlmap.

---

### Finding 1 – Boolean-Based SQL Injection

One request contained conditional expressions similar to:

```sql
CASE WHEN (2574=2574) THEN 1 ELSE 0 END
```

### Why it is Suspicious

Boolean-based SQL Injection modifies application logic by introducing conditions that evaluate as either **true** or **false**.

Attackers compare the application's responses to determine whether injected SQL statements are successfully executed by the backend database.

This technique is commonly used when error messages are suppressed.

### Analyst Assessment

The observed payload strongly indicated that the attacker was validating SQL Injection rather than simply scanning the application.

---

### Finding 2 – Error-Based SQL Injection

Another request abused the SQL function:

```sql
EXTRACTVALUE(...)
```

### Why it is Suspicious

Functions such as **EXTRACTVALUE()** intentionally trigger database errors that may reveal backend information.

Attackers use this technique to disclose:

- database version;
- user accounts;
- schema information;
- internal SQL responses.

### Analyst Assessment

This payload demonstrated progression beyond initial testing and into database fingerprinting.

---

### Finding 3 – UNION-Based SQL Injection

Additional requests included:

```sql
UNION ALL SELECT
```

### Why it is Suspicious

UNION-based SQL Injection attempts to merge attacker-controlled queries with legitimate application queries.

When successful, attackers can retrieve:

- database contents;
- usernames;
- passwords;
- application secrets;
- sensitive business data.

### Analyst Assessment

The presence of UNION-based payloads indicated that the attacker had advanced from vulnerability validation toward information extraction.

---

## Step 4 – Database Enumeration & Command Execution Attempts

After successfully validating the SQL Injection vulnerability, the attacker progressed to more advanced exploitation techniques aimed at gathering database information and assessing the possibility of operating system command execution.

---

### Finding 4 – Database Enumeration

Several requests targeted the following database object:

```sql
information_schema.tables
```

### Why it is Suspicious

`information_schema` is a system database that stores metadata about the database structure.

Attackers frequently enumerate these tables to identify:

- Database names
- Table names
- Column names
- Sensitive application data

This behavior typically represents the transition from vulnerability validation to information gathering.

### Analyst Assessment

The attacker clearly progressed beyond basic SQL Injection testing and began enumerating the backend database structure, indicating an attempt to prepare for data extraction.

---

### Finding 5 – Operating System Command Execution Attempt

One of the observed payloads attempted to execute:

```sql
EXEC xp_cmdshell('cat ../../../etc/passwd')
```

### Why it is Suspicious

`xp_cmdshell` is an extended stored procedure that allows Microsoft SQL Server to execute operating system commands.

Although disabled by default in modern SQL Server deployments, it remains one of the most abused techniques following successful SQL Injection attacks.

The observed payload attempted to read:

```text
../../../etc/passwd
```

which is commonly used to determine whether operating system command execution is possible.

### Analyst Assessment

The presence of this payload demonstrated that the attacker attempted to move beyond database interaction toward operating system command execution.

However, no endpoint telemetry or additional evidence indicated that the command executed successfully.

---

## Step 5 – HTTP Response Analysis

The final phase focused on determining how the application responded to the injected payloads.

Every malicious request received:

```
HTTP/1.1 200 OK
```

### Why it is Significant

An HTTP **200 OK** response confirms that:

- the web server successfully processed the request;
- the SQL payload reached the application layer;
- the application generated a valid response.

While a **200 OK** response does **not** prove successful data extraction or operating system compromise, it strongly suggests that the application accepted and processed the malicious SQL statements.

### Analyst Assessment

The HTTP responses demonstrated that the attacker successfully interacted with the backend application.

However, the available telemetry did not provide evidence confirming:

- database dumping;
- sensitive data disclosure;
- successful `xp_cmdshell` execution;
- server compromise.


# Evidence Correlation

No single log entry was sufficient to classify this incident.

Instead, multiple independent observations were correlated throughout the investigation.

## Web Server Evidence

✅ Multiple SQL Injection payloads observed.

✅ Requests originated from a single external source.


## Attacker Behavior

✅ Automated exploitation framework identified.

✅ User-Agent explicitly reported:

```
sqlmap/1.7.2#stable
```


## SQL Injection Evidence

✅ Boolean-based SQL Injection.

✅ Error-based SQL Injection.

✅ UNION-based SQL Injection.


## Enumeration Evidence

✅ Database metadata enumeration using:

```
information_schema.tables
```


## Post-Exploitation Attempts

✅ Operating system command execution attempted using:

```
xp_cmdshell
```

No supporting evidence confirmed successful execution.


## HTTP Response Evidence

✅ Every malicious request received:

```
HTTP 200 OK
```

confirming that the payloads successfully reached the application layer.


## Analyst Conclusion

The investigation demonstrated a structured SQL Injection attack conducted using the automated exploitation framework **sqlmap**.

Evidence confirmed that the attacker progressed through multiple attack phases:

- vulnerability validation;
- database fingerprinting;
- metadata enumeration;
- operating system command execution attempts.

Although no evidence confirmed successful compromise of the server or data exfiltration, the application processed all malicious requests, indicating successful interaction between the injected SQL statements and the backend database.

The incident was therefore classified as a **True Positive SQL Injection attack** requiring remediation of the vulnerable application.


# MITRE ATT&CK Techniques Identified

| Tactic | Technique | ID | Evidence from Investigation |
|---------|-----------|------|----------------------------|
| Initial Access | Exploit Public-Facing Application | **T1190** | Multiple SQL Injection payloads targeted the public-facing web application. |
| Discovery | Software Discovery | **T1518** | The attacker enumerated database objects using `information_schema.tables`. |
| Discovery | System Information Discovery | **T1082** | SQL payloads attempted to identify backend database characteristics and system information. |
| Execution | Command and Scripting Interpreter | **T1059** | The attacker attempted to execute operating system commands using `xp_cmdshell`. |
| Collection | Data from Information Repositories | **T1213** | UNION-based payloads and metadata enumeration attempted to identify sensitive database information. |


# Indicators of Compromise (IoCs)

## Network Indicators

| Type | Indicator |
|------|-----------|
| Source IP | `118.194.247.28` |


## HTTP Indicators

| Type | Indicator |
|------|-----------|
| User-Agent | `sqlmap/1.7.2#stable` |
| URI Pattern | `/index.php?id=` |
| HTTP Status | `200 OK` |


## SQL Indicators

| Type | Indicator |
|------|-----------|
| SQL Function | `EXTRACTVALUE()` |
| SQL Technique | `UNION SELECT` |
| SQL Procedure | `xp_cmdshell` |
| Enumeration Target | `information_schema.tables` |


# Incident Classification

| Field | Value |
|------|------|
| Classification | **True Positive** |
| Severity | High |
| Attack Type | Automated SQL Injection |
| Exploitation Tool | sqlmap 1.7.2 |
| Escalated to IR | Yes |


# Escalation Note

**True Positive.**

The investigation confirmed an automated SQL Injection attack performed using **sqlmap 1.7.2** against a public-facing web application.

Web server logs revealed multiple SQL Injection techniques, including **Boolean-based**, **Error-based**, and **UNION-based** payloads, followed by **database enumeration** and **operating system command execution attempts** using `xp_cmdshell`.

Although no evidence confirmed successful command execution, data exfiltration, or server compromise, every malicious request received **HTTP 200 OK**, demonstrating that the payloads successfully reached the application layer and interacted with the backend database.

Based on the correlation of web server logs, attacker behavior, SQL payload analysis, and HTTP responses, the incident was classified as a confirmed **True Positive SQL Injection attack** requiring remediation of the vulnerable application.

# Recommendations

- Immediately validate and remediate the SQL Injection vulnerability.
- Implement parameterized queries (prepared statements).
- Apply strict server-side input validation.
- Disable `xp_cmdshell` if not operationally required.
- Deploy or tune Web Application Firewall (WAF) rules to detect SQL Injection payloads.
- Review application and database logs for signs of unauthorized data access.
- Perform additional threat hunting to identify similar attacks across other public-facing applications.

# Lessons Learned

- Automated exploitation frameworks such as **sqlmap** generate multiple SQL Injection techniques during a single attack, allowing analysts to observe the attack progression from vulnerability validation to attempted exploitation.
- An **HTTP 200 OK** response confirms that the application processed the malicious request, but it does **not** independently prove successful data theft or operating system compromise.
- Correlating payload content, attacker behavior, and HTTP responses provides a far more accurate assessment than relying on any single indicator.
- Database enumeration and `xp_cmdshell` attempts are strong indicators that an attacker is progressing beyond vulnerability discovery toward post-exploitation objectives.

# Key Takeaways

This investigation demonstrates how a structured SQL Injection attack evolves from vulnerability validation to attempted database enumeration and command execution.

Rather than relying solely on the alert, the investigation correlated **web server logs**, **HTTP responses**, **SQL payload analysis**, and **attacker behavior** to reconstruct the attack sequence and accurately determine its impact.

The incident highlights the importance of distinguishing between **successful payload processing** and **confirmed post-exploitation activity**, allowing analysts to reach evidence-based conclusions and provide meaningful remediation recommendations.
