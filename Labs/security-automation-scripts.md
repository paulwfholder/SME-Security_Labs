## **Automation with Scripting Lab: Streamlining Security Tasks Using Python and Bash**

### Lab Objective:
This lab will teach you to automate routine security tasks using Python and Bash scripts. You’ll learn how to script processes like log parsing, alert generation, threat intelligence lookups, and automated remediation. Automating these tasks is essential for efficient, large-scale security operations, saving time and reducing human error.

---

### **Scenario**:
As a member of the security team, you’re tasked with developing scripts that can automate frequent, repetitive tasks. You’ll build scripts for tasks such as log analysis, detecting suspicious activities, querying threat intelligence databases, and performing quick remediation steps (e.g., blocking IPs). 

This lab includes four main parts:
1. **Log Parsing and Alert Generation**
2. **Threat Intelligence Lookup Automation**
3. **Automated Incident Response**
4. **Scheduling and Monitoring Scripts**

---

### **Part 1: Log Parsing and Alert Generation**

1. **Objective**: Create a Python script that parses logs for specific patterns, such as failed login attempts, and generates alerts for any anomalies.

2. **Python Script for Log Parsing**:
   - Write a Python script, `log_parser.py`, to process log files (e.g., from Windows Event Logs, Apache access logs).
   - Use **regular expressions** to detect patterns. For instance, if monitoring for brute-force attempts, look for multiple failed logins from the same IP.
   - Example:
     ```python
     import re
     
     log_file = "access.log"
     failed_logins = {}

     with open(log_file, 'r') as file:
         for line in file:
             if "Failed login" in line:
                 ip = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                 if ip:
                     ip_address = ip.group()
                     failed_logins[ip_address] = failed_logins.get(ip_address, 0) + 1

     for ip, count in failed_logins.items():
         if count > 5:
             print(f"Alert: Potential brute-force attack detected from IP {ip}")
     ```

3. **Customizing Alerts**:
   - Configure the script to alert if failed login attempts from a single IP exceed a threshold (e.g., 5 attempts within 10 minutes).
   - Test the script by simulating failed logins and verify that it captures the incidents.

4. **Saving and Reporting Alerts**:
   - Modify the script to log alerts into a separate file, `alerts.log`, and append timestamps for each alert.
   - Optional: Add an email notification function using the `smtplib` module in Python to send alerts to the security team.

---

### **Part 2: Threat Intelligence Lookup Automation**

1. **Objective**: Automate lookups against threat intelligence databases (e.g., VirusTotal or AlienVault OTX) to check for known malicious IPs or domains.

2. **Setting Up API Access**:
   - Obtain API keys from threat intelligence platforms like VirusTotal. (Note: Some platforms may have rate limits for free users.)
   - Store the API key securely in an environment variable.

3. **Python Script for Threat Intelligence Lookup**:
   - Create a Python script, `threat_lookup.py`, that accepts an IP address or domain as input, queries the threat intelligence API, and returns results.
   - Example using VirusTotal API:
     ```python
     import requests
     import os

     api_key = os.getenv("VIRUSTOTAL_API_KEY")
     ip = "192.168.1.1"
     url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
     
     headers = {
         "x-apikey": api_key
     }
     
     response = requests.get(url, headers=headers)
     if response.status_code == 200:
         data = response.json()
         if data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious") > 0:
             print(f"Alert: IP {ip} is flagged as malicious in VirusTotal.")
         else:
             print(f"IP {ip} is clean.")
     else:
         print("Error: Failed to query VirusTotal API.")
     ```

4. **Batch Processing**:
   - Extend the script to accept a list of IPs/domains from a file and perform lookups in bulk.
   - Log the results to a file, `threat_intel_results.log`, with timestamps.

---

### **Part 3: Automated Incident Response**

1. **Objective**: Develop Bash scripts to perform basic remediation actions, such as blocking an IP on a firewall or isolating an endpoint.

2. **Blocking an IP Address Using Firewall Rules**:
   - Write a Bash script, `block_ip.sh`, to block an IP address using `iptables` on Linux.
   - Example:
     ```bash
     #!/bin/bash
     IP_TO_BLOCK=$1
     
     if [ -z "$IP_TO_BLOCK" ]; then
         echo "Usage: ./block_ip.sh <IP_ADDRESS>"
         exit 1
     fi
     
     iptables -A INPUT -s $IP_TO_BLOCK -j DROP
     echo "Blocked IP $IP_TO_BLOCK"
     ```

   - Run the script with `./block_ip.sh <IP_ADDRESS>` to block a specific IP.
   - Test the script by blocking a known test IP and verifying it’s no longer accessible.

3. **Isolating an Endpoint on the Network**:
   - Create a script to disable network interfaces temporarily or modify network routes to isolate a machine. For example, using `ifconfig` to bring down an interface:
     ```bash
     #!/bin/bash
     IFACE="eth0"
     ifconfig $IFACE down
     echo "Isolated endpoint by disabling interface $IFACE"
     ```
   - Execute the script to isolate the machine and then bring the interface back up by running `ifconfig $IFACE up`.

4. **Restoration and Documentation**:
   - Document how to unblock IPs and re-enable network interfaces to ensure recovery is possible after testing.

---

### **Part 4: Scheduling and Monitoring Scripts**

1. **Objective**: Automate the execution of the above scripts using cron jobs and configure logs to monitor their performance.

2. **Scheduling with Cron**:
   - Set up cron jobs to run the `log_parser.py` script every 10 minutes to scan logs and generate alerts.
     ```bash
     */10 * * * * /usr/bin/python3 /path/to/log_parser.py >> /path/to/alerts.log 2>&1
     ```

   - Schedule the `threat_lookup.py` script to check a daily list of IPs/domains, ensuring that only known threats are flagged.

3. **Setting Up Logging**:
   - Direct output from each script into log files. For instance, append output of `block_ip.sh` to `remediation.log` to keep a record of blocked IPs and remediation actions taken.
   - Set up a weekly cron job to back up log files to a secure location for audit purposes.

4. **Monitoring for Script Failures**:
   - Configure cron to send an email notification if any script fails or logs unexpected errors.
   - Use `mailx` or a similar utility to send a summary email of script activity (like blocked IPs) each day.

---

### **Lab Deliverables**:

1. **Scripts Repository**:
   - Provide the Python and Bash scripts for log parsing, threat intelligence lookup, and incident response.

2. **Example Output Logs**:
   - Submit sample output logs for each script, such as `alerts.log`, `threat_intel_results.log`, and `remediation.log`.

3. **Documentation**:
   - Include instructions on how to configure API access, run the scripts, and set up cron jobs.

4. **Reflection Questions**:
   - Which scripts were the most challenging to implement, and how could they be improved?
   - How effective was automation in reducing the time spent on repetitive tasks?
   - What additional tasks could be automated in the future?

---

This Automation Lab equips you with the skills to streamline security workflows using Python and Bash, enabling efficient, scalable management of common security tasks. 
