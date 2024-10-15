# Intern-Intelligence--Incident-Response-

### Incident Response Report: Simulated Security Breach

#### **Scenario**
A simulated security breach was conducted on a web application environment (DVWA) monitored by the Wazuh security platform. The breach involved introducing a Trojan malware into the system to emulate an attack aimed at compromising sensitive data.

- **Attack Type**: Trojan Horse File (detected as a malicious file).
- **Infrastructure**: DVWA (Damn Vulnerable Web Application) for the target, Kali Linux for launching attacks, and Wazuh Manager for monitoring and alerts.
- **Monitoring Tools**: Wazuh Manager, Wazuh Agent on Kali Linux, and VMware-based virtual environment.

---

#### **Incident Response Phases**

1. **Incident Detection**
   - The Wazuh Manager detected multiple alerts classified as "Trojaned version of file detected" under the Malware Detection module. These alerts triggered from the Wazuh agent installed on the target system, with rule ID `510`.
   - **Detection Event Details**:
     - **Rule Description**: Host-based anomaly detection: Trojaned version of file detected.
     - **Timestamp**: Multiple timestamps as per log alerts (shown in the Wazuh UI).
     - **Impact**: The detection indicates a potential Trojan horse file, which could allow unauthorized access to sensitive data and further malicious activities.
   - **Source**: The Wazuh agent provided alerts from the infected system (IP: 192.168.147.135).

   **Detection Tools Used**:
   - **Wazuh Malware Detection** for automatic scanning of potential threats.
   - **Rootcheck** for anomaly detection in system files.
![image](https://github.com/user-attachments/assets/cfcf1e14-f726-4751-9b75-e16dddeee7d8)



---

2. **Incident Containment**
   - **Containment Measures**:
     - **Isolate the Affected VM**: The Kali Linux VM, where the agent detected the Trojan, was isolated from the network to prevent lateral movement of the malware.
     - **Stop Vulnerable Services**: Services vulnerable to exploitation, such as web applications (DVWA), were temporarily halted to prevent further exploitation.
   - **Actions Taken**:
     - The network interface for the infected VM was set to "host-only" to block external connections.
     - Immediate scanning was triggered across all endpoints using Wazuh to ensure no other endpoints were compromised.

---

3. **Incident Eradication**
   - **Eradication Steps**:
     - **Manual Deletion of Malware**: The infected file paths, as detected by Wazuh alerts, were manually deleted from the compromised system.
     - **Malware Scanning**: Additional scans using malware detection modules were performed to ensure all traces of the Trojan were removed.
     - **Update of Security Policies**: The `ossec.conf` file was updated to prevent future occurrences of such malware by improving detection rules.
     
   - **Tools Used**:
     - **Wazuh Manager**: For malware alerting.
     - **Manual Actions**: Deletion of malicious files based on the provided path.
   
   - **Results**:
     - No further malware was detected after conducting additional scans.


#!/bin/bash

# Extract file path from Wazuh alert
FILE_PATH=$1

# Delete the file
if [ -f "$FILE_PATH" ]; then
    echo "Deleting trojan file: $FILE_PATH"
    rm -f "$FILE_PATH"
else
    echo "File not found: $FILE_PATH"
fi

----
<active-response>
  <command>delete_trojan</command>
  <location>local</location> <!-- Or "any" if you want this response to apply to all systems -->
  <rules_id>510</rules_id>  <!-- ID of the rule that triggers the response -->
  <timeout>0</timeout> <!-- No timeout; it executes immediately -->
  <repeated_offenders>no</repeated_offenders>
</active-response>


<command>
  <name>delete_trojan</name>
  <executable>active-response/bin/delete_trojan.sh</executable>
  <expect>any</expect>
  <timeout_allowed>yes</timeout_allowed>
</command>

---



---


4. **Incident Recovery**
   - **Recovery Steps**:
     - **Restore Services**: Once the infected files were removed, and the system was declared clean, services were gradually restored, starting with critical ones.
     - **System Monitoring**: Continuous monitoring using Wazuh was set up for the next 48 hours to detect any unusual activities or reinfection attempts.
     - **Patching and Updating**: The system was patched to eliminate the vulnerabilities that allowed the malware entry, including updating the web application to the latest version.

---

5. **Post-Incident Analysis**
   - **Review**:
     - **Initial Compromise**: The entry point for the malware was identified as the insecure configuration of the web application (DVWA), where an attacker could upload malicious files.
     - **Detection Efficiency**: Wazuh's malware detection module worked effectively, catching the Trojan immediately, but further automation (like auto-removal) could enhance the response time.
     - **Containment**: Isolating the infected system worked well to prevent further propagation.
     - **Eradication**: Manual removal of malware is effective but slow. Automating this process could save time in a real breach.
     - **Recovery**: The recovery process involved proper service restoration and monitoring. However, ensuring no vulnerable services remained unpatched required more thorough review.
   
   - **Gaps Identified**:
     - **Automation**: The response would benefit from automated malware removal upon detection.
     - **Alerting**: Faster alerting mechanisms via email or SMS for critical threats.
     - **File Path Visibility**: Ensure the Wazuh agent provides the exact file path consistently in future incidents.
   
   - **Recommendations for Improvement**:
     - **Improve Automation**: Configure `ossec.conf` to perform automatic deletion of detected malicious files.
     - **Patching and Updates**: Regularly update and patch all web applications and systems to avoid vulnerabilities.
     - **Comprehensive Logging**: Ensure full logging capabilities in Wazuh, especially for file paths of detected malware.
     - **Periodic Testing**: Conduct regular breach simulations to ensure the readiness of the incident response team.

---

### **Conclusion**
The simulated breach demonstrated the effectiveness of Wazuh in detecting and alerting on a Trojan malware attack. The incident was successfully contained and eradicated, with improvements identified for automation and alerting.
