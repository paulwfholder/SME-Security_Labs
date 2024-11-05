## **Incident Response (IR) Lab: Analyzing a Compromised Endpoint**

### Lab Objective:
This lab will guide you through the process of investigating a potential compromise on an endpoint. You'll simulate an incident, gather and analyze forensic artifacts, create a timeline, and document findings. By the end, you’ll have practiced essential incident response skills, such as identifying indicators of compromise (IOCs) and drafting an incident report.

---

### **Scenario**:
Imagine you’re part of an incident response team for a tech company. The company’s monitoring system flagged suspicious activity on an employee's endpoint: unauthorized access to sensitive data and signs of a potential backdoor. Your task is to investigate this incident, contain the compromise, and analyze the malicious actions taken on the system.

The lab will be divided into four main parts:
1. **Initial Incident Detection and Preparation**
2. **Data Collection and Forensic Analysis**
3. **Constructing a Timeline and Analyzing Findings**
4. **Creating an Incident Report and Recommendations**

---

### **Part 1: Initial Incident Detection and Preparation**

1. **Environment Setup**:
   - Set up a Windows VM as your compromised endpoint for analysis. Isolate it from the main network.
   - Install Sysmon (as configured in the previous lab) to log process, file, and network activities, or use a SIEM solution if available.

2. **Simulating Compromise on the Endpoint**:
   - **Malicious Access Simulation**: Run a PowerShell command to simulate unauthorized access and credential dumping:
     ```powershell
     Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'
     ```
   - **Backdoor Creation**: Place a reverse shell script on the endpoint to simulate a backdoor:
     ```powershell
     nc.exe -L -p 4444 -e cmd.exe
     ```
   - **Data Exfiltration Simulation**: Simulate data exfiltration by copying files to a suspicious folder:
     ```powershell
     cp "C:\SensitiveData\client_data.txt" "C:\Windows\Temp\staging_area\"
     ```

3. **Immediate Response Actions**:
   - Disconnect the compromised endpoint from the network.
   - Isolate the VM and prepare to gather forensic data (event logs, memory dump, etc.) to analyze the activities of the simulated attacker.

---

### **Part 2: Data Collection and Forensic Analysis**

1. **Collecting Initial Forensic Data**:
   - **Memory Dump**: Capture a memory dump using a tool like **DumpIt** or **WinPMem**.
   - **Event Logs**: Collect relevant logs (Security, Sysmon, and PowerShell event logs) to trace the attacker’s activity.
   - **Network Connections**: Capture any open network connections or suspicious IP addresses associated with the endpoint. Use `netstat` to document:
     ```powershell
     netstat -ano
     ```

2. **Analyzing Collected Data**:
   - **Memory Analysis**: Analyze the memory dump for evidence of unauthorized processes, open network connections, or credential theft tools (e.g., mimikatz traces).
     - Use **Volatility** with plugins like `pslist` (to list processes) and `netscan` (to analyze open network connections).
   - **Log Analysis**:
     - **Security Logs**: Check for abnormal login attempts or privilege escalation attempts. Review Event ID 4624 (successful logon) and 4672 (special privileges assigned).
     - **Sysmon Logs**: Look for Event IDs related to suspicious processes (e.g., `Invoke-Mimikatz`) and network activity (e.g., connections to unusual IPs).
   - **File System Review**: Look for suspicious files or scripts in critical directories (e.g., `C:\Windows\Temp\staging_area`). Verify file hashes using `Get-FileHash` to identify potential malware.

3. **Identifying Indicators of Compromise (IOCs)**:
   - Create a list of IOCs from the analysis, including:
     - Processes: `mimikatz.exe`, `nc.exe`
     - Network Connections: IP addresses associated with the reverse shell
     - Files: Any unexpected or hidden files in system directories, such as `client_data.txt` in `C:\Windows\Temp\`

---

### **Part 3: Constructing a Timeline and Analyzing Findings**

1. **Timeline Construction**:
   - Use the logs and forensic data to create a timeline of the attacker’s actions on the system. Arrange the events in chronological order, starting with the initial compromise.
   - Example timeline entries:
     - **12:15 PM**: Unauthorized user login detected (Event ID 4624).
     - **12:16 PM**: Mimikatz tool execution detected (PowerShell script event).
     - **12:18 PM**: Reverse shell setup on port 4444 with `nc.exe`.
     - **12:20 PM**: File `client_data.txt` moved to staging area in `C:\Windows\Temp\`.
   
2. **Analyzing Findings**:
   - Evaluate the attacker’s motives based on actions: credential dumping (suggests privilege escalation attempt), reverse shell setup (indicates persistence), and data staging (implies potential exfiltration).
   - Identify potential methods for entry, lateral movement, and data theft.

---

### **Part 4: Creating an Incident Report and Recommendations**

1. **Documenting the Incident**:
   - **Incident Summary**: Write a summary of the incident, including how it was detected, suspected goals of the attacker, and the tools they used.
   - **Timeline of Events**: Include your constructed timeline in the report.
   - **Key IOCs**: List all IOCs identified, including malicious processes, IP addresses, and file hashes.

2. **Root Cause Analysis**:
   - Determine the most likely root cause of the compromise based on available evidence. Was it an external attack, or could it have been insider misuse?
   - Include possible gaps in existing defenses that allowed the attacker to gain unauthorized access.

3. **Remediation and Recommendations**:
   - **Containment**: Describe actions taken to isolate the endpoint and prevent further damage (e.g., disconnecting the endpoint from the network).
   - **Eradication**: Outline steps for removing malicious files and processes from the endpoint.
   - **Recovery**: Define steps for safely reconnecting the endpoint to the network after thorough cleanup.
   
   - **Preventative Recommendations**:
     - Deploy an EDR solution for enhanced detection and response.
     - Configure network segmentation to limit lateral movement opportunities.
     - Enforce multi-factor authentication (MFA) to protect against credential theft.
     - Increase employee training on phishing awareness, as phishing is often an initial attack vector.

4. **Reflection Questions**:
   - How did you identify each IOC, and what were the main indicators that signaled the compromise?
   - What could have prevented this incident? How could monitoring or access controls be improved?
   - What additional steps would you take if you identified similar activity on other endpoints?

---

### **Lab Deliverables**:

1. **Incident Report**:
   - A detailed report summarizing each stage of the investigation, including the timeline, IOCs, and root cause analysis.
   
2. **Forensic Artifacts**:
   - Screenshots of logs and forensic artifacts that illustrate the compromised activities (e.g., PowerShell logs, Sysmon entries, memory dump analysis).
   - File hashes and other IOCs extracted from the compromised endpoint.

3. **Recommendations Summary**:
   - A summary of specific actions for containment, eradication, and recovery, as well as long-term recommendations for improving the organization’s security posture.

4. **Reflection and Discussion**:
   - Answers to the reflection questions, emphasizing incident detection, investigation process, and suggestions for a more resilient environment.

---

This lab will provide a comprehensive, hands-on approach to investigating a compromised endpoint and creating a structured response to incidents. 
