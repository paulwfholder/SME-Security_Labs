## **Threat Hunting Lab: Identifying and Mitigating Hidden Threats**

### Lab Objective:
This lab will guide you through the process of proactive threat hunting, where you will search for potential threats within an environment rather than waiting for alerts to detect malicious activity. You will learn to craft hypotheses based on real-world attack patterns, investigate anomalies, identify indicators of compromise (IOCs), and apply tactics to prevent undetected threats from exploiting network resources.

---

### **Scenario**:
Your organization suspects there may be advanced persistent threats (APTs) operating within the network. Although no specific alerts have been raised, you, as a threat hunter, are tasked with proactively searching for signs of hidden or sophisticated threats. The organization has provided access to SIEM logs, endpoint telemetry, and network traffic data.

In this lab, you will:
1. **Understand the Threat Hunting Methodology and Set Up the Environment**
2. **Formulate and Test Hypotheses Based on Threat Intelligence**
3. **Investigate Suspicious Activities Using Data Analysis and Forensic Techniques**
4. **Identify and Document Indicators of Compromise (IOCs)**
5. **Create and Implement Mitigation Steps to Prevent Future Threats**

---

### **Part 1: Threat Hunting Methodology and Environment Setup**

1. **Review Threat Hunting Fundamentals**:
   - Understand the purpose of threat hunting and how it differs from traditional security monitoring.
   - Learn about the **MITRE ATT&CK** framework, which categorizes tactics and techniques used by attackers. Familiarize yourself with several tactics, such as **Initial Access**, **Persistence**, **Privilege Escalation**, and **Lateral Movement**.

2. **Set Up Threat Hunting Environment**:
   - Use the SIEM from the previous lab as your primary data source.
   - Install **Kibana** (if using Elastic Stack) or another log visualization tool to help analyze and visualize logs.
   - Ensure endpoint telemetry from EDR solutions is connected, and confirm network traffic data from firewalls, VPN, and DNS logs are available.

3. **Baseline the Network**:
   - Generate baseline data for normal user and network activity.
   - Document typical login times, application usage, and network traffic patterns.

---

### **Part 2: Formulating and Testing Hypotheses**

1. **Define Hypotheses Based on Common Attack Patterns**:
   - Use the **MITRE ATT&CK** framework to create hypotheses about potential attack vectors:
     - **Hypothesis 1**: A threat actor might be using **malicious PowerShell scripts** to execute commands remotely.
     - **Hypothesis 2**: Suspicious **lateral movement** attempts across the network may indicate privilege escalation activities.
     - **Hypothesis 3**: Abnormal **outbound traffic** to unknown IPs could signal data exfiltration efforts.

2. **Plan and Prepare Testing Strategies**:
   - Outline the steps to test each hypothesis, including specific logs to review, tools to use, and IOCs to search for.
   - Set up filters in the SIEM to capture activities that align with these hypotheses, such as detecting PowerShell executions or analyzing login behavior across multiple machines.

3. **Perform Baseline Comparisons**:
   - Compare suspected abnormal activities against the baseline data.
   - Flag any unusual deviations, such as login attempts from uncommon IP ranges or traffic spikes to unknown domains.

---

### **Part 3: Investigating Suspicious Activities**

1. **PowerShell Script Detection**:
   - Query for recent PowerShell executions using the SIEM’s search capabilities.
   - Filter for suspicious command-line arguments, such as `-encodedcommand`, which is often used to obfuscate commands:
     ```plaintext
     process_name: powershell.exe AND command_line: *-encodedcommand*
     ```
   - Review the decoded commands for any malicious activity and check the user accounts initiating these commands.

2. **Lateral Movement Analysis**:
   - Look for **event logs** indicating **remote desktop (RDP) connections** or **network logons** to other workstations or servers.
   - Use the following log identifiers in Windows:
     - **Event ID 4624**: An account was successfully logged on.
     - **Event ID 4648**: A logon attempt was made with explicit credentials.
   - Cross-reference the timestamps of these events with the typical login times from baseline data, and flag unusual logins.

3. **Data Exfiltration Monitoring**:
   - Analyze outbound network traffic logs, focusing on spikes or patterns outside of regular business hours.
   - Use the SIEM to filter logs for large data transfers to external IPs, especially those associated with unknown or suspicious domains.
   - Use **Wireshark** or **Bro/Zeek** to drill down into specific packets, inspecting payload sizes and protocols.

---

### **Part 4: Identifying and Documenting Indicators of Compromise (IOCs)**

1. **Catalog IOCs from Investigations**:
   - As you discover suspicious activity, document any IOCs found. These could include:
     - Malicious IP addresses or domains linked to data exfiltration.
     - File hashes for any identified malware or malicious scripts.
     - Usernames or machine names associated with unauthorized access.

2. **Creating an IOC Database**:
   - Store the IOCs in a shared document or an IOC management platform.
   - Assign categories and risk levels to each IOC based on its severity and threat impact.

3. **Generating Alerts for IOCs**:
   - Configure alerts in the SIEM to monitor for the newly discovered IOCs. For example:
     - If a user accesses a flagged IP or domain, trigger an alert.
     - Alert if PowerShell scripts with suspicious commands reappear on any endpoint.

---

### **Part 5: Mitigation Steps and Reporting**

1. **Implement Mitigations for Threats Found**:
   - Based on the findings, implement preventive controls:
     - Restrict PowerShell execution policies to limit unauthorized script use.
     - Apply firewall rules to block outbound traffic to the flagged IPs.
     - Set stricter authentication and network segmentation policies to hinder lateral movement.

2. **Prepare a Threat Hunting Report**:
   - **Executive Summary**: Outline the objective of the threat hunt, key findings, and implications for the organization’s security posture.
   - **Hypotheses and Findings**: Detail each hypothesis, the investigation steps taken, and the outcomes.
   - **IOC Summary**: Include a list of IOCs discovered, such as IP addresses, file hashes, and suspicious commands.
   - **Recommendations**: Suggest changes in monitoring, access controls, or endpoint configurations based on the identified threats.

3. **Reflection and Continuous Improvement**:
   - Reflect on the effectiveness of the hunt, noting which hypotheses provided the most actionable insights.
   - Suggest areas for improving future threat hunting, such as additional log sources or refined alert criteria.

---

### **Lab Deliverables**:

1. **Threat Hunting Report**:
   - Submit a detailed report with the executive summary, findings, IOCs, and recommendations.

2. **Screenshots of Findings**:
   - Capture key screenshots from the SIEM showing flagged IOCs, suspicious PowerShell commands, and lateral movement events.

3. **IOC List and Alert Configuration**:
   - Provide a list of the IOCs identified and the SIEM alert rules configured for monitoring.

4. **Reflection Questions**:
   - How did you prioritize which hypotheses to investigate first?
   - Which types of logs or data sources proved most valuable during the hunt?
   - What improvements would you suggest for future hunts to increase detection effectiveness?

---

This Threat Hunting Lab reinforces skills in proactive security by teaching you how to identify hidden threats, analyze suspicious activity, and establish defenses against advanced attacks.
