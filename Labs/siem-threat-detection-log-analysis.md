## **Security Information and Event Management (SIEM) Lab: Real-Time Threat Detection and Log Analysis**

### Lab Objective:
This lab will introduce you to using a Security Information and Event Management (SIEM) system to collect, correlate, and analyze security event logs in real-time. You’ll set up a SIEM environment, create custom alerts, investigate potential incidents, and generate reports. The skills developed here are essential for monitoring, detecting, and responding to security threats in complex network environments.

---

### **Scenario**:
Your organization has recently deployed a SIEM solution to centralize and analyze log data from multiple sources across the network. The company’s SOC team suspects suspicious activity and requests your help to configure alerts, analyze correlated logs, and identify potential security threats.

The lab is divided into five main parts:
1. **Setting Up a SIEM Environment**
2. **Configuring Log Sources**
3. **Creating and Testing SIEM Alerts**
4. **Investigating Security Incidents**
5. **Reporting and Improving SIEM Use**

---

### **Part 1: Setting Up a SIEM Environment**

1. **Selecting a SIEM Tool**:
   - For this lab, you can use an open-source SIEM platform like **Elastic Stack (ELK)**, **Wazuh**, or **Splunk (free version)**.
   - Install the selected SIEM on a virtual machine or cloud instance.

2. **Configuring Essential Components**:
   - **Log Collection**: Install **Filebeat** or an equivalent log shipper on client machines (Windows/Linux VMs) to forward logs to the SIEM.
   - **Data Parsing and Ingestion**: Set up ingestion pipelines to parse logs correctly, especially from Windows Event Logs, firewall logs, and web server access logs.
   - **Indexing and Storage**: Create indices to store logs by category (e.g., security events, network traffic).

3. **Basic SIEM Configuration**:
   - Configure the SIEM to retain data for a set period (e.g., 30 days) and set up role-based access controls to protect sensitive logs.

---

### **Part 2: Configuring Log Sources**

1. **Configuring Windows Event Logs**:
   - Set up **Winlogbeat** (or equivalent) on Windows VMs to send Event Logs (Security, Application, and System) to the SIEM.
   - Verify that important security events, such as logon attempts and privilege escalations, are captured.

2. **Configuring Firewall and Network Device Logs**:
   - Configure the firewall to send logs to the SIEM via syslog. Ensure logs capture critical information like IP connections, dropped packets, and blocked ports.
   - Set up network device logs (such as from routers or switches) to log activity at the network perimeter.

3. **Configuring Web Server Logs**:
   - If the organization hosts web services, configure web servers (e.g., Apache or NGINX) to send access and error logs to the SIEM for monitoring suspicious requests.

4. **Testing Log Collection**:
   - Generate sample events on each log source (e.g., a failed login attempt on Windows, a blocked IP on the firewall) and verify that these events are captured and viewable in the SIEM.

---

### **Part 3: Creating and Testing SIEM Alerts**

1. **Setting Up Basic Alerts**:
   - Create alerts in the SIEM based on common threats:
     - **Brute-force Logins**: Set an alert to trigger if there are more than five failed login attempts from the same IP within 10 minutes.
     - **Unusual Outbound Traffic**: Set an alert for outbound traffic spikes from internal IPs to external IPs on uncommon ports.
     - **Malicious File Downloads**: Trigger an alert for HTTP requests that match patterns indicative of malicious file extensions (e.g., `.exe`, `.bat`).

2. **Configuring Threshold-Based Alerts**:
   - Define threshold-based alerts to monitor for significant deviations from baseline activity:
     - **High CPU Usage on Critical Servers**: If CPU usage on a monitored server exceeds 80% for more than 10 minutes, trigger an alert.
     - **Network Traffic Volume Increase**: Trigger alerts if outbound traffic exceeds a daily average by a defined percentage, which could indicate data exfiltration.

3. **Customizing Correlation Rules**:
   - Set up correlation rules that combine different log sources:
     - **Lateral Movement Detection**: If an account logs in to multiple hosts within a short time, trigger an alert for potential lateral movement.
     - **Suspicious Logon with High Data Transfer**: Alert if a user logs in and then generates a high amount of outbound network traffic, indicating possible data theft.

4. **Testing Alerts**:
   - Simulate each alert scenario:
     - Attempt failed logins on a Windows VM to trigger a brute-force alert.
     - Simulate network activity by sending large data packets to an external IP.
   - Verify that the SIEM triggers the correct alerts, and adjust any rules as necessary.

---

### **Part 4: Investigating Security Incidents**

1. **Reviewing Alerts and Correlated Events**:
   - When an alert is triggered, use the SIEM’s dashboard to investigate correlated events. For instance, if a brute-force alert is triggered, review both the login attempts and related network traffic for that IP address.

2. **Analyzing Log Patterns**:
   - Use log search functions to analyze suspicious patterns:
     - **User Behavior**: Query login records to check if an account has exhibited unusual login times or locations.
     - **Network Traffic Analysis**: Check if a compromised machine has made multiple outbound connections to unknown IPs.

3. **Identifying Indicators of Compromise (IOCs)**:
   - Identify key IOCs such as IP addresses, file hashes, or domains found in logs.
   - Create a watchlist within the SIEM for these IOCs to monitor future occurrences and facilitate tracking.

4. **Evidence Collection**:
   - Export relevant logs, screenshots of alerts, and other evidence for documentation and further analysis.

---

### **Part 5: Reporting and Improving SIEM Use**

1. **Creating an Incident Report**:
   - Document the incident in a report with:
     - **Summary**: Briefly explain the alert type and suspected threat.
     - **Timeline**: Outline the sequence of events, from detection to response.
     - **Logs and Evidence**: Include log samples and IOCs.
     - **Impact Assessment**: Estimate the potential impact of the threat.

2. **Fine-Tuning SIEM Alerts**:
   - Based on the incident investigation, adjust alert thresholds and refine correlation rules to reduce false positives and increase detection accuracy.

3. **Recommendations for Ongoing Monitoring**:
   - Suggest additional data sources or logs to monitor, such as DNS queries or VPN logs.
   - Propose integrating threat intelligence feeds to enrich the SIEM’s detection capabilities.

4. **Reflection Questions**:
   - Which alerts were most useful for identifying suspicious activity? Were any alerts redundant or ineffective?
   - How could correlation rules be further refined to detect advanced attack techniques?

---

### **Lab Deliverables**:

1. **SIEM Dashboard Screenshot**:
   - Capture the main SIEM dashboard showing active alerts and status indicators.

2. **Sample Log Exports**:
   - Provide exports of logs for key events related to the incident, such as login attempts, network traffic spikes, and firewall blocks.

3. **Incident Report**:
   - Submit a detailed incident report documenting the investigation and conclusions.

4. **Reflection Questions**:
   - Which parts of the SIEM setup were most challenging, and how could they be improved?
   - What adjustments would you make to the alert and correlation rules based on this lab?

---

This lab immerses you in SIEM setup, log analysis, and incident response, simulating the real-time monitoring and alerting tasks performed in a SOC.
