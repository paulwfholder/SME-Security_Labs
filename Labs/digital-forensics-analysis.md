## **Digital Forensics Lab: Investigating a Malware-Infected System**


### Lab Objective:
In this lab, you'll conduct a forensic investigation on a malware-infected system. You’ll practice capturing forensic images, analyzing file system artifacts, identifying malware signatures, and documenting the investigation. This lab aims to build skills in data preservation, file analysis, and generating forensic reports, which are essential in digital forensics roles.

---

### **Scenario**:
You’re a digital forensics investigator for a consulting firm. A client suspects malware has compromised one of their employee’s computers. The machine shows signs of unusual behavior, such as slow performance and unexpected network activity. Your task is to preserve evidence, analyze the file system for indicators of malware, and draft a forensic report.

The lab will be divided into five parts:
1. **Initial Setup and Evidence Acquisition**
2. **File System and Registry Analysis**
3. **Malware Analysis and Signature Identification**
4. **Network Traffic and Persistence Mechanisms Analysis**
5. **Creating a Forensic Report and Documentation**

---

### **Part 1: Initial Setup and Evidence Acquisition**

1. **Environment Setup**:
   - Use a Windows VM as the compromised system. Ensure the VM is isolated from your main network to prevent any potential malware from spreading.
   - Set up a separate Linux VM with forensic tools like **Autopsy** (Sleuth Kit), **Volatility**, and **Wireshark** for analysis.

2. **Create a Forensic Disk Image**:
   - Use **FTK Imager** or **dd** on Linux to create a forensic image of the infected machine. This ensures data preservation while allowing for detailed offline analysis.
   - If using FTK Imager, follow these steps:
     - Open FTK Imager and select **File > Create Disk Image**.
     - Select the appropriate source and specify the destination for the image file.
     - Hash the image using MD5 and SHA-1 to ensure integrity.

3. **Verify the Disk Image**:
   - Use hashing tools to calculate the hash values of the original and copied disk images. Document these hash values as they will be critical in ensuring the evidence’s integrity.
   - Record your findings and verify that the hashes match, showing that the image is an exact duplicate of the original disk.

---

### **Part 2: File System and Registry Analysis**

1. **Mounting the Disk Image**:
   - Mount the forensic image in **Autopsy** (or another forensic tool) to analyze the file system structure without altering the image.
   - Navigate through the directories and identify suspicious files, such as recently created executables in system folders (e.g., `C:\Windows\Temp`, `C:\ProgramData`, and `C:\Users\Public`).

2. **Identify Suspicious Executables**:
   - Look for unusual executables, especially those with non-standard filenames, in critical folders. Use file-hashing tools within Autopsy to check if these executables match known malware signatures.
   - Use VirusTotal or another malware repository to look up hashes and confirm if they’re associated with known threats.

3. **Registry Analysis**:
   - Extract the Windows Registry hives (e.g., **NTUSER.DAT**, **SYSTEM**, **SOFTWARE**) from the forensic image.
   - Focus on key registry entries that can provide clues about persistence mechanisms:
     - **Run** keys (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`)
     - **Startup Locations**: Check if the malware has embedded itself to execute on boot.
   - Document any suspicious entries, such as unknown executables or scheduled tasks.

---

### **Part 3: Malware Analysis and Signature Identification**

1. **Identify Malware Characteristics**:
   - Check the executables you’ve identified for suspicious attributes (e.g., creation time mismatches, lack of digital signatures).
   - Examine any obfuscated or encoded scripts, particularly PowerShell or VBS scripts, as these are common vectors for malware payloads.

2. **Static Analysis**:
   - Extract the malware from the disk image and perform a static analysis in a controlled environment:
     - Check the **file properties**, metadata, and **strings** within the executable to identify potential IOCs (Indicators of Compromise).
     - Use a tool like **Strings** or **BinText** to review the binary for suspicious text, URLs, or IP addresses.

3. **Dynamic Analysis** (Optional):
   - If you have the resources, you may set up a malware sandbox (e.g., **Cuckoo Sandbox**) to run the malware and observe its behavior, such as network connections and file modifications.
   - Document any observable actions, such as files created, registry keys modified, or network connections made.

---

### **Part 4: Network Traffic and Persistence Mechanisms Analysis**

1. **Network Traffic Analysis**:
   - If the VM shows unusual network activity, capture packets using **Wireshark** or review existing network logs (if available).
   - Filter the captured packets to look for communication with suspicious IP addresses or unusual ports, common signs of a Command and Control (C2) server.
   - Document any URLs, IPs, or domains the malware attempts to reach, as these can be used as IOCs for further investigation.

2. **Persistence Mechanisms**:
   - Investigate methods the malware uses to maintain persistence:
     - Scheduled tasks (`schtasks /query` to view all tasks)
     - Registry **Run** keys
     - Services that automatically start at boot
   - Document each persistence mechanism you find, detailing how the malware remains active even after reboots.

---

### **Part 5: Creating a Forensic Report and Documentation**

1. **Drafting the Forensic Report**:
   - Begin by documenting the investigation’s objective, the timeline of actions, and an executive summary for the client.
   - **Evidence Collection**: Include details on how you acquired and verified the forensic disk image.
   - **Analysis Findings**: Describe each piece of suspicious evidence, such as malware signatures, network traffic, and registry keys, with screenshots where possible.
   - **Indicators of Compromise**: List all IOCs found, including file hashes, IP addresses, registry entries, and filenames.

2. **Incident Summary and Conclusions**:
   - Summarize the impact of the malware infection, including potential data exfiltration or lateral movement within the network.
   - State your conclusions about the malware’s purpose, such as data theft, espionage, or system disruption.

3. **Recommendations**:
   - Suggest steps for the client to remove the malware, such as:
     - Removing affected files and registry entries
     - Updating antivirus and firewall settings
     - Patching vulnerabilities that may have allowed the malware to enter
   - Include preventative measures to avoid future compromises, such as employee security awareness training, EDR implementation, and regular audits of network traffic.

4. **Reflection Questions**:
   - How did you identify the malware, and which forensic techniques were most helpful?
   - If the malware attempted data exfiltration, what steps would you recommend to prevent future data loss?
   - How would you improve the company’s overall security posture based on this incident?

---

### **Lab Deliverables**:

1. **Forensic Report**:
   - A comprehensive report detailing each step of the investigation, including screenshots, hash values, and registry entries.

2. **List of IOCs**:
   - An organized list of indicators of compromise for the client’s reference and any future incident responses.

3. **Evidence Artifacts**:
   - Provide the collected artifacts in a secure, accessible format, including:
     - Disk image hashes
     - Captured network packets
     - Malware binaries (if safe to share)

4. **Summary and Recommendations**:
   - A summary of findings and a list of practical recommendations for improving the endpoint’s and network’s security.

5. **Reflection and Discussion**:
   - Answers to reflection questions, providing insight into the digital forensic process and how it helps strengthen cybersecurity defenses.

---

This lab provides hands-on experience with forensic acquisition, artifact analysis, and incident documentation.
