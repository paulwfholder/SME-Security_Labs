## **Firewall Configuration and Intrusion Detection Lab: Protecting a Network from Malicious Traffic**

### Lab Objective:
This lab will guide you through configuring a firewall and setting up an intrusion detection system (IDS) to monitor and block malicious network traffic. You’ll configure firewall rules, deploy Snort (an open-source IDS), analyze IDS alerts, and interpret logs. This lab builds skills crucial for detecting and blocking network intrusions.

---

### **Scenario**:
As a security engineer at a medium-sized enterprise, you are tasked with strengthening the network’s defenses. Recently, the company has noticed an increase in unauthorized connection attempts from external IPs. You will configure a firewall to block suspicious traffic and set up an IDS to monitor for and alert on suspicious patterns.

The lab is divided into five main parts:
1. **Setting Up the Firewall**
2. **Configuring Basic Firewall Rules**
3. **Installing and Configuring an Intrusion Detection System (IDS)**
4. **Testing Firewall and IDS Configurations**
5. **Reporting and Recommendations**

---

### **Part 1: Setting Up the Firewall**

1. **Environment Setup**:
   - Use a Linux VM (Ubuntu or CentOS) as your firewall system. Ensure it has two network interfaces:
     - **External Interface**: Connected to the internet or an emulated external network.
     - **Internal Interface**: Connected to a protected network with one or more client machines (VMs) to simulate a corporate environment.

2. **Installing Firewall Software**:
   - Install **UFW** (Uncomplicated Firewall) or **iptables** for configuring firewall rules.
   - Enable UFW and set the default policy to deny all incoming connections:
     ```bash
     sudo ufw default deny incoming
     sudo ufw default allow outgoing
     ```

3. **Verifying the Network Setup**:
   - Confirm that the Linux VM can communicate with the internal client VMs and the external network to simulate real-world firewall protection.
   - Test basic connectivity between the internal and external network interfaces.

---

### **Part 2: Configuring Basic Firewall Rules**

1. **Allowing Essential Services**:
   - Configure rules to allow specific services that the company needs:
     - **SSH** access from a secure IP range (e.g., only allow SSH from your internal network).
     - **Web Server Traffic**: Allow HTTP/HTTPS (ports 80 and 443) traffic to simulate a public-facing web server.
   - Example:
     ```bash
     sudo ufw allow from <internal_network_ip_range> to any port 22
     sudo ufw allow 80/tcp
     sudo ufw allow 443/tcp
     ```

2. **Blocking Suspicious Traffic**:
   - Block traffic from specific IP ranges known for malicious activity:
     ```bash
     sudo ufw deny from <malicious_ip_range>
     ```

3. **Enabling Logging for Rule Violations**:
   - Enable UFW logging to capture denied connections for further analysis:
     ```bash
     sudo ufw logging on
     ```

4. **Testing the Firewall Rules**:
   - From an external machine, attempt to connect to various ports to verify that only permitted traffic is allowed and that unauthorized attempts are logged.

---

### **Part 3: Installing and Configuring an Intrusion Detection System (IDS)**

1. **Installing Snort**:
   - Install **Snort** on the Linux VM (the same machine where you set up the firewall).
   - Update Snort’s rule set to include signatures for common attack patterns.

2. **Basic Snort Configuration**:
   - Configure Snort to listen on the internal network interface and log suspicious activity:
     ```bash
     sudo snort -i <internal_interface> -c /etc/snort/snort.conf -A console
     ```
   - Customize the `snort.conf` file to specify the network segments to monitor and to set up logging paths.

3. **Creating Snort Rules for Common Threats**:
   - Write a few basic Snort rules to detect specific threats:
     - **Port Scans**: Detect repeated connection attempts to multiple ports from a single IP.
       ```plaintext
       alert tcp any any -> any 22 (msg:"SSH scan detected"; flags:S; threshold:type both, track by_src, count 5, seconds 60; sid:1000001; rev:1;)
       ```
     - **Brute-force Login Attempts**: Detect multiple failed login attempts.
       ```plaintext
       alert tcp any any -> any 22 (msg:"Brute-force SSH login detected"; flags:S; threshold:type both, track by_src, count 10, seconds 60; sid:1000002; rev:1;)
       ```
     - **Malicious File Download**: Detect downloads of specific file types commonly associated with malware.
       ```plaintext
       alert http any any -> any any (msg:"Malicious file download detected"; content:".exe"; sid:1000003; rev:1;)
       ```

4. **Running Snort in Alert Mode**:
   - Start Snort in alert mode to display real-time alerts for detected threats. Test the rules by performing actions (e.g., SSH scans or file downloads) that match your Snort rules.

---

### **Part 4: Testing Firewall and IDS Configurations**

1. **Simulating External Attacks**:
   - Use a tool like **Nmap** from an external VM to simulate a port scan:
     ```bash
     nmap -p 1-1000 <firewall_external_ip>
     ```
   - Confirm that the firewall blocks unauthorized attempts and that Snort logs the scanning activity as an alert.

2. **Testing Brute-Force Detection**:
   - Attempt to log in to the firewall via SSH multiple times from an external IP to simulate a brute-force attack.
   - Verify that Snort generates alerts for repeated login attempts as per your custom rule.

3. **File Download Detection**:
   - From a client VM within the internal network, attempt to download a `.exe` file from the internet.
   - Verify that Snort detects this as a potential threat and logs an alert.

4. **Analyzing IDS Alerts**:
   - Review Snort alerts and logs to confirm that the IDS rules accurately detected and alerted on each test case.
   - Note any IP addresses, ports, or protocols associated with detected threats and analyze the potential severity.

---

### **Part 5: Reporting and Recommendations**

1. **Creating an Incident Report**:
   - Document each simulated attack and the corresponding firewall/IDS response. Include:
     - **Attack Type**: Describe the type of attack (e.g., port scan, brute-force).
     - **Detected Activity**: Summarize what Snort and the firewall detected and how they responded.
     - **Evidence**: Provide screenshots of logs or Snort alerts for each event.

2. **Analyzing Effectiveness**:
   - Evaluate the effectiveness of your firewall and IDS configuration based on the results.
   - Document any gaps in detection or response, such as undetected activities or false positives.

3. **Preventive Recommendations**:
   - Suggest additional firewall rules or IDS signatures to further strengthen the network’s defenses:
     - Consider adding geo-blocking to restrict connections from certain regions.
     - Enable rate limiting or honeypots for high-risk ports like SSH.

4. **Reflection Questions**:
   - How well did the firewall and IDS configurations work together to detect and block suspicious activities?
   - What modifications would improve the detection of unauthorized network access?
   - How might this setup be scaled for an enterprise environment with multiple network segments?

---

### **Lab Deliverables**:

1. **Firewall Configuration File**:
   - Provide a copy of your UFW/iptables configuration file, including all firewall rules.

2. **Custom Snort Rules**:
   - Share the custom Snort rules you wrote, along with descriptions of each rule’s purpose.

3. **Snort Alerts and Logs**:
   - Include screenshots or saved logs of Snort alerts for each simulated attack scenario.

4. **Incident Report**:
   - Write an incident report that documents each detected threat and the firewall/IDS response.

5. **Recommendations and Reflection**:
   - Summarize recommendations for further improvement and answer the reflection questions.

---

This lab offers a practical approach to understanding firewall rules, configuring an IDS, and analyzing network traffic for potential threats.
