## **Incident Response and Forensics Lab: Investigating and Responding to a Security Breach**

### Lab Objective:
In this lab, you’ll walk through the steps of an incident response (IR) process, including detecting and containing an incident, collecting and analyzing forensic data, and creating an incident report. You’ll learn the critical skills needed to investigate potential security breaches, analyze digital evidence, and apply IR procedures.

---

### **Scenario**:
Your company has detected signs of a potential security breach. Suspicious files were found on a Windows server, and unusual login patterns indicate possible unauthorized access. Your task is to investigate the incident, collect forensic evidence, analyze it for indicators of compromise (IOCs), and create a final report with your findings and recommendations.

The lab is divided into six main parts:
1. **Preparation: Setting Up Tools for Incident Response**
2. **Detection and Analysis: Identifying Potential Indicators of Compromise**
3. **Containment and Eradication: Securing the System**
4. **Data Collection: Gathering Evidence**
5. **Analysis and Report Creation**
6. **Recovery and Post-Incident Recommendations**

---

### **Part 1: Preparation - Setting Up Tools for Incident Response**

1. **Preparing Your IR Environment**:
   - Set up a Windows VM to serve as the target system that has potentially been compromised.
   - Download and install the following essential IR tools on a separate “investigator” VM or USB:
     - **Sysinternals Suite** (includes tools like Autoruns, Process Explorer, and PsExec).
     - **Volatility** (for memory analysis).
     - **Wireshark** (for network traffic analysis).
     - **FTK Imager** (for forensic image capture).
     - **KAPE** (Kroll Artifact Parser and Extractor, for log and artifact collection).
   - Ensure all tools are up-to-date to avoid compatibility issues.

2. **Creating a Baseline**:
   - Create a clean baseline of the system’s state by recording a snapshot, which will help you identify any modifications during analysis.
   - Document known processes, services, and network connections.

---

### **Part 2: Detection and Analysis - Identifying Potential Indicators of Compromise (IOCs)**

1. **Log Review**:
   - Review the **Windows Event Logs** for unusual activity:
     - **Security Logs**: Look for failed/successful logon attempts (Event IDs 4624 and 4625).
     - **Application Logs**: Note any application crashes or unusual errors that coincide with suspicious logons.
   - Use **PowerShell** to search for events around a suspected incident time:
     ```powershell
     Get-EventLog -LogName Security -After "2023-11-01 00:00:00" -Message "*logon*"
     ```

2. **Network Traffic Analysis**:
   - Capture a few minutes of network traffic from the compromised system using **Wireshark**.
   - Filter for unusual connections:
     - **Outbound Traffic to Unknown IPs**: Filter for IPs outside the company network or known threat sources.
     - **Unusual Ports**: Look for communication over uncommon ports, which may indicate a command-and-control (C2) connection.

3. **File System Changes**:
   - Use **Sysinternals Autoruns** to look for new or suspicious startup programs that may have been added by an attacker.
   - Check for recently modified or created files in sensitive directories, especially in `C:\Users\<username>\AppData`, `C:\Windows\System32`, and `C:\ProgramData`.

4. **Memory Capture**:
   - Capture the system’s memory using **FTK Imager** or **WinPmem** for later analysis with **Volatility**.

---

### **Part 3: Containment and Eradication - Securing the System**

1. **Disconnecting the Affected System**:
   - Disconnect the system from the network to prevent the attacker from further access or data exfiltration.

2. **Isolating Processes**:
   - Identify suspicious processes using **Process Explorer** and **Task Manager**.
   - Suspend any suspicious processes that are actively using network resources.

3. **Disabling Compromised User Accounts**:
   - If the logs indicate unauthorized access via certain accounts, temporarily disable these accounts and reset their passwords.
   - Change all administrator passwords as a precaution.

4. **Applying Emergency Patches**:
   - Check for missing security patches and apply them, especially if the attacker exploited a known vulnerability.

---

### **Part 4: Data Collection - Gathering Evidence**

1. **Collecting Logs and Artifacts with KAPE**:
   - Use **KAPE** to collect and export essential log files and forensic artifacts:
     - **Windows Event Logs**: Security, Application, and System logs.
     - **Registry Hives**: `NTUSER.DAT`, `SAM`, `SECURITY`, `SOFTWARE`.
     - **File Modification Timestamps**: Recently accessed files.
     - **Prefetch Files**: Analyze program execution and times.

2. **Memory Analysis**:
   - Analyze the memory dump captured in Part 2 using **Volatility**.
   - Key analysis steps:
     - **Listing Running Processes**: Check for suspicious processes that might be malware.
       ```bash
       volatility -f memory.img --profile=Win10x64 pslist
       ```
     - **Network Connections**: Identify any established or listening connections.
       ```bash
       volatility -f memory.img --profile=Win10x64 netscan
       ```
     - **Extracting Strings**: Search for plain-text indicators like URLs, IPs, or command-line arguments.

3. **File Integrity Check**:
   - Compare hashes of core system files against known-good hashes to detect tampering.
   - Run a hash check on files in `System32` and `Program Files` directories to confirm their integrity.

4. **Collecting Suspicious Files**:
   - Extract any suspicious files found, such as `.exe`, `.dll`, or `.bat` files, for further analysis in a controlled environment (sandbox).

---

### **Part 5: Analysis and Report Creation**

1. **Analyzing Collected Evidence**:
   - Review each forensic artifact to build a timeline of the attacker’s actions:
     - **Initial Access**: How did the attacker gain access?
     - **Privilege Escalation**: Did they attempt to gain higher privileges?
     - **Persistence Mechanisms**: Did they create new user accounts, services, or scheduled tasks?
     - **Lateral Movement**: Did they attempt to access other machines or systems on the network?

2. **Root Cause Analysis**:
   - Based on the evidence, identify the most likely point of entry and the vulnerabilities exploited.
   - Identify any malware or tools used by the attacker to gain or maintain access.

3. **Creating an Incident Report**:
   - **Executive Summary**: Brief overview of the incident, including key findings and the attack impact.
   - **Technical Details**: Detailed explanation of the attack sequence, IOCs, affected systems, and vulnerabilities exploited.
   - **Evidence Documentation**: Include relevant logs, screenshots, and analysis results as supporting evidence.
   - **Recommendations**: Provide actionable steps to prevent similar incidents in the future, such as enhanced monitoring, patches, or access control policies.

---

### **Part 6: Recovery and Post-Incident Recommendations**

1. **System Restoration**:
   - Restore the compromised system from a known-good backup.
   - Reinstall the operating system if needed to remove all traces of the attack.

2. **Implementing Security Enhancements**:
   - Apply strict access controls and multifactor authentication (MFA) for sensitive systems.
   - Enable enhanced logging and monitoring on high-value systems.

3. **Security Awareness Training**:
   - Conduct training sessions to educate employees on phishing, social engineering, and other common attack methods.

4. **Reviewing Incident Response Plan**:
   - Evaluate the effectiveness of the current IR plan and update it to address any identified gaps.
   - Conduct a post-mortem meeting with the incident response team to discuss lessons learned.

---

### **Lab Deliverables**:

1. **Collected Artifacts**:
   - Provide a sample of the collected logs, memory dump, and any suspicious files you found.

2. **Incident Report**:
   - Submit a detailed incident report with all relevant findings, evidence, and recommendations.

3. **Analysis Scripts and Queries**:
   - Share any PowerShell commands, Wireshark filters, or Volatility scripts used for analysis.

4. **Reflection Questions**:
   - How would you improve your incident detection capabilities based on this experience?
   - What was the most challenging aspect of gathering evidence in this lab?
   - How can you further secure similar systems from this type of attack?

---

This lab provides hands-on experience with incident response and forensics, focusing on detecting, analyzing, and responding to security breaches.
