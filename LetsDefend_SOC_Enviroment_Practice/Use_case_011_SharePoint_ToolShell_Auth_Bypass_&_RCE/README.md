# SOC342 - SharePoint ToolShell Auth Bypass and RCE Investigation (CVE-2025-53770)

## Incident Summary

This investigation focused on a critical web attack alert related to CVE-2025-53770, a SharePoint ToolShell vulnerability associated with authentication bypass and remote code execution (RCE). The alert was triggered by a suspicious unauthenticated POST request sent from an external IP address to a SharePoint server, targeting the ToolPane.aspx endpoint with a large request body and a suspicious referer.

During the investigation, additional endpoint telemetry revealed post-exploitation activity on the SharePoint server, including encoded PowerShell execution, malicious ASPX file creation inside SharePoint directories, compilation of a payload using csc.exe, and PowerShell access to ASP.NET application configuration secrets. Based on the combined web and host evidence, the incident was classified as a True Positive, with strong indicators of successful exploitation and attacker-controlled code execution on the target server.


| Field                    | Value                                                                                                                                                 |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Event ID**             | 320                                                                                                                                                   |
| **Alert Name**           | SOC342 - CVE-2025-53770 SharePoint ToolShell Auth Bypass and RCE                                                                                      |
| **Severity**             | Critical                                                                                                                                              |
| **Category**             | Web Attack                                                                                                                                            |
| **Detection Time**       | Jul 22, 2025, 01:07 PM                                                                                                                                |
| **Hostname**             | SharePoint01                                                                                                                                          |
| **Source IP**            | `107.191.58.76`                                                                                                                                       |
| **Destination IP**       | `172.16.20.17`                                                                                                                                        |
| **HTTP Method**          | POST                                                                                                                                                  |
| **Requested URL**        | `/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx`                                                                                        |
| **User-Agent**           | `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0`                                                                    |
| **Referer**              | `/_layouts/SignOut.aspx`                                                                                                                              |
| **Content-Length**       | `7699`                                                                                                                                                |
| **Device Action**        | Allowed                                                                                                                                               |
| **Alert Trigger Reason** | Suspicious unauthenticated POST request targeting ToolPane.aspx with large payload size and spoofed referer indicative of CVE-2025-53770 exploitation |


**imagen_alert**
