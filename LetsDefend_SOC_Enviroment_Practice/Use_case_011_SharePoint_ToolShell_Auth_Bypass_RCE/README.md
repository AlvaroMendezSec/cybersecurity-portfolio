# SOC342 – SharePoint ToolShell Authentication Bypass & Remote Code Execution (CVE-2025-53770)

## Executive Summary

This investigation analyzed a **critical exploitation attempt targeting an on-premises Microsoft SharePoint Server** vulnerable to **CVE-2025-53770 (ToolShell Authentication Bypass & Remote Code Execution)**.

The investigation began with a suspicious unauthenticated HTTP POST request targeting **ToolPane.aspx**, a known exploitation vector associated with the ToolShell vulnerability. By correlating **proxy logs**, **endpoint telemetry**, and **PowerShell execution history**, multiple post-exploitation activities were identified.

The compromised SharePoint server executed **Base64-encoded PowerShell**, compiled a malicious payload using **csc.exe**, generated a rogue ASPX component capable of downloading attacker-controlled content, and accessed sensitive **ASP.NET MachineKey** configuration.

Based on the available evidence, the incident was classified as a **True Positive** representing a successful exploitation attempt requiring immediate Incident Response.

---

# Alert Overview

| Field | Value |
|---------|--------|
| Severity | Critical |
| Category | Web Attack |
| Rule | SOC342 – SharePoint ToolShell Authentication Bypass & RCE |
| CVE | CVE-2025-53770 |
| Target Host | SharePoint01 |
| Source IP | 107.191.58.76 |
| Destination IP | 172.16.20.17 |
| HTTP Method | POST |
| Request URI | /_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx |
| Detection Source | Proxy Logs |
| Device Action | Allowed |

---

# Investigation Timeline

| Time | Activity |
|------|----------|
| 13:07 | Alert generated for suspicious POST request targeting ToolPane.aspx |
| 13:07 | Proxy logs reviewed and exploitation indicators identified |
| 13:08 | Endpoint investigation initiated |
| 13:08 | Encoded PowerShell execution identified |
| 13:08 | Payload compilation using csc.exe observed |
| 13:09 | Malicious ASPX component creation confirmed |
| 13:09 | ASP.NET MachineKey access detected |
| 13:10 | Incident classified as True Positive and escalated |

---

# Investigation Objectives

The objective of this investigation was to determine:

- Whether the SharePoint server was targeted using CVE-2025-53770.
- Whether exploitation succeeded.
- Whether post-exploitation activity occurred.
- Whether attacker-controlled payloads were executed.
- Whether Incident Response escalation was required.
