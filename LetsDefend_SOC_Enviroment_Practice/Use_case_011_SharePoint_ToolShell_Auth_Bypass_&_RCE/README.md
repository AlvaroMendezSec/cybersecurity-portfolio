# SOC342 - SharePoint ToolShell Auth Bypass and RCE Investigation (CVE-2025-53770)

## Incident Summary

This investigation focused on a critical web attack alert related to CVE-2025-53770, a SharePoint ToolShell vulnerability associated with authentication bypass and remote code execution (RCE). The alert was triggered by a suspicious unauthenticated POST request sent from an external IP address to a SharePoint server, targeting the ToolPane.aspx endpoint with a large request body and a suspicious referer.

During the investigation, additional endpoint telemetry revealed post-exploitation activity on the SharePoint server, including encoded PowerShell execution, malicious ASPX file creation inside SharePoint directories, compilation of a payload using csc.exe, and PowerShell access to ASP.NET application configuration secrets. Based on the combined web and host evidence, the incident was classified as a True Positive, with strong indicators of successful exploitation and attacker-controlled code execution on the target server.
