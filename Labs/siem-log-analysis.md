## **SIEM and Log Analysis Lab: Detecting and Responding to Threats Using a SIEM**

### Lab Objective:
This lab will guide you through using a Security Information and Event Management (SIEM) tool to detect, analyze, and respond to potential security incidents. You'll practice querying and interpreting logs, creating custom alerts, and building a basic dashboard. This lab will help you understand how SIEM systems play a central role in monitoring network and endpoint security.

---

### **Scenario**:
Imagine you are part of the SOC (Security Operations Center) team for a financial institution. There have been reports of suspicious login attempts and unexpected file changes on key servers. Your task is to monitor and analyze these activities using the SIEM tool, set up alerts, and respond to any potential threats.

The lab will be divided into five main parts:
1. **SIEM Setup and Log Ingestion**
2. **Basic Log Analysis and Queries**
3. **Creating Alerts and Custom Rules**
4. **Building a Dashboard for Monitoring**
5. **Incident Response and Reporting**

---

### **Part 1: SIEM Setup and Log Ingestion**

1. **Setting Up the SIEM Environment**:
   - Use an open-source SIEM tool, such as **Elastic Stack (ELK)**, **Splunk Free**, or **Graylog**.
   - Deploy the SIEM on a Linux VM with sufficient storage and processing power for log ingestion.

2. **Ingesting Sample Logs**:
   - Configure log forwarding from a Windows VM and a Linux VM to simulate real-time log collection.
   - Enable logging for:
     - **Windows Security Logs**: Forward logs like authentication, login attempts, and privilege changes.
     - **Linux Syslogs**: Collect logs from `/var/log/auth.log`, `/var/log/syslog`, and others.
   - Use **Filebeat** or **Winlogbeat** for Windows log forwarding and **Syslog** for Linux to transmit logs to the SIEM tool.

3. **Setting Up a Test Scenario**:
   - Simulate abnormal events to create data for analysis:
     - **Unauthorized Login Attempts**: Use brute-force login attempts with different usernames to generate failed login events.
     - **File Access Violations**: Access a sensitive file directory on the Linux system and attempt unauthorized changes.
   - This setup will provide a dataset for identifying security anomalies and refining your alerting rules.

---

### **Part 2: Basic Log Analysis and Queries**

1. **Exploring Ingested Logs**:
   - Review recent logs within the SIEM interface to familiarize yourself with the data format.
   - Search for key event types:
     - **Authentication Logs**: Look for Event IDs related to logon attempts on Windows (e.g., Event ID 4625 for failed logons).
     - **File Access Events**: Review logs for unexpected access to sensitive files on the Linux system.

2. **Creating Queries for Basic Threat Detection**:
   - Write basic queries to filter specific event types:
     - **Windows Failed Login Attempts**:
       ```json
       EventID:4625 AND TargetUserName:<username>
       ```
     - **Linux Unauthorized File Access**:
       ```json
       syslog_program: "audit" AND action: "denied"
       ```
   - Run each query and analyze the results to detect any unusual patterns, such as repeated login attempts from the same IP or unexpected access by low-privilege accounts.

3. **Identifying Potential Threats in Logs**:
   - Review logs for indicators of brute-force attacks, privilege escalation attempts, or suspicious file access.
   - Note any IP addresses, user accounts, or system processes associated with unusual activity for further investigation.

---

### **Part 3: Creating Alerts and Custom Rules**

1. **Designing Alert Criteria**:
   - Define alert criteria based on common attack vectors:
     - **Multiple Failed Login Attempts**: Trigger an alert if more than five failed login attempts occur within a minute from a single IP.
     - **File Access Violations**: Set an alert if unauthorized access attempts are detected on sensitive files.

2. **Configuring Alerts in the SIEM Tool**:
   - Create a new alert in the SIEM tool based on the criteria:
     - **Failed Login Alert**: Write a query and configure the alert to notify you when the login threshold is exceeded.
     - **Unauthorized File Access Alert**: Set the alert to detect and notify you when unauthorized file access occurs.

3. **Testing Alerts**:
   - Trigger each alert by generating matching log events:
     - Attempt multiple failed logins from one IP address within a short timeframe to test the brute-force detection alert.
     - Attempt unauthorized access to a sensitive directory on Linux to test the file access alert.
   - Verify that each alert fires correctly and adjust thresholds as needed for tuning.

---

### **Part 4: Building a Dashboard for Monitoring**

1. **Designing the Dashboard Layout**:
   - Plan out a dashboard to monitor key metrics:
     - **Authentication Events**: Failed and successful logins by time and by IP address.
     - **File Access Violations**: Unauthorized access attempts on sensitive files.
     - **User Activity**: Top accounts by login frequency and by unauthorized attempts.

2. **Adding Data Visualizations**:
   - **Failed Logins Over Time**: Create a bar chart showing failed logins to quickly identify any brute-force login patterns.
   - **Sensitive File Access**: Add a list view of recent unauthorized access attempts to sensitive files.
   - **IP Geolocation Map** (if possible): Display a map visualization showing the locations of incoming login attempts for anomaly detection.

3. **Customizing the Dashboard for SOC Monitoring**:
   - Organize visualizations and metrics in a way that allows quick situational awareness of potential threats.
   - Ensure that the dashboard auto-refreshes to show the most recent data in real time.

---

### **Part 5: Incident Response and Reporting**

1. **Investigating an Alert**:
   - When an alert fires (e.g., for repeated failed login attempts), go into the SIEM to investigate.
   - Review the specific event details and surrounding context to confirm if it’s a false positive or an actual incident.
   - Identify any related logs, such as additional login attempts from the same IP, or other actions taken by the user.

2. **Documenting the Incident**:
   - Draft an incident report including:
     - **Incident Summary**: Describe the event, such as “Suspicious Login Attempts Detected.”
     - **Analysis**: Explain how you detected the incident, the actions taken, and any indicators that suggest further investigation.
     - **Response and Remediation**: Document steps for containing the incident, such as blocking the IP address, resetting user passwords, or escalating the investigation if needed.

3. **Forensic Analysis** (Optional):
   - For a more advanced investigation, download the associated logs and analyze them further using log parsing or scripting tools.
   - Focus on identifying root causes, such as whether the IP address is associated with known botnets or if other endpoints are impacted.

4. **Preventive Recommendations**:
   - Based on your analysis, provide recommendations for the SOC:
     - Implement IP blocks for repeated failed login sources.
     - Enforce stricter authentication policies, such as account lockouts or CAPTCHA challenges after multiple failures.
     - Increase alerting for suspicious login attempts on high-value assets.

---

### **Lab Deliverables**:

1. **Custom Alerts**:
   - Document the alerts you created, including thresholds and logic. Screenshots of alert configurations are recommended.
   
2. **SIEM Queries**:
   - Save your queries for detecting failed logins, unauthorized file access, and any other patterns you identified.
   
3. **Dashboard Screenshots**:
   - Provide screenshots of your completed dashboard, including key visualizations and metrics.

4. **Incident Report**:
   - Write an incident report that summarizes at least one detected event, including analysis, response actions, and recommendations.

5. **Reflection Questions**:
   - Which log types were the most helpful for detecting suspicious activity? Why?
   - How would you improve your alerting criteria based on the results?
   - How can this lab help enhance the SOC’s real-time monitoring capabilities?

---

This lab emphasizes hands-on experience in configuring and using a SIEM to monitor, detect, and respond to security events.
