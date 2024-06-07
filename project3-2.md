---
layout: post
title: Wazuh - EDR
description: 
image: assets/images/osticket.jpg
nav-menu: false
show_tile: false
---

This documentation produces a set of best practices and insights into configuring and utilizing Wazuh for enhanced threat detection, incident response, and compliance monitoring, contributing to a stronger cybersecurity defense framework.

**Objective**: Investigate and demonstrate the practical application of Wazuh in detecting and mitigating cybersecurity threats, thereby displaying its utility in improving the security posture of organizations.

**Outcome**: Produce a set of best practices and insights into configuring and utilizing Wazuh for enhanced threat detection, incident response, and compliance monitoring, contributing to a stronger cybersecurity defense framework. 

---

## Preface

In the dynamic field of cybersecurity, the capacity for timely threat detection and response is crucial. Wazuh stands out as an open-source security monitoring platform, offering comprehensive tools for threat detection, incident response, and compliance. This project aims to explore Wazuh’s capabilities, demonstrating its application in enhancing organizational security.

We will deploy Wazuh in a controlled environment to highlight its effectiveness against various security threats, such as malware and unauthorized access, and to monitor compliance. The project highlights the pivotal role of open-source tools in making advanced security features accessible, supporting organizations of varying sizes and sectors.

The expected outcome is a detailed understanding of Wazuh’s deployment, configuration, and integration into security practices, offering insights into its scalability and flexibility. Our goal is to equip cybersecurity professionals with the knowledge to leverage Wazuh effectively, fostering a proactive security stance in the face of evolving cyber threats. 

This endeavor aims to contribute to the cybersecurity community by demonstrating practical applications and benefits of Wazuh, underscoring the importance of open-source solutions in contemporary cybersecurity strategies. 

---

## Wazuh Overview

### Key Features of Wazuh

[Wazuh](https://wazuh.com/) is a versatile open-source security monitoring platform offering a comprehensive suite of features designed to enhance threat detection, incident response, and compliance management. Its key features include: 

1. **Host-based Intrusion Detection (HIDS):** Wazuh performs real-time analysis of host-level events, such as file changes, process executions, and network connections, to detect and respond to potential security threats. 
2. **Log Management and Analysis:** Wazuh collects, normalizes, and analyzes log data from various sources, including system logs, application logs, and network devices, providing organizations with centralized visibility into their IT infrastructure.
3. **File Integrity Monitoring (FIM):** Wazuh monitors critical system files and directories for unauthorized modifications, alerting administrators to potential tampering or compromise.
4. **Vulnerability Detection:** Wazuh integrates with vulnerability databases to identify known vulnerabilities in software and configurations, allowing organizations to proactively address security risks.
5. **Threat Intelligence Integration:** Wazuh incorporates threat intelligence feeds to enrich security event data and enhance threat detection capabilities, enabling organizations to stay ahead of emerging threats. 
6. **Compliance Monitoring:** Wazuh includes predefined compliance rulesets for regulatory frameworks such as PCI-DSS, GDPR, and CIS benchmarks, facilitating compliance auditing and reporting.

### Architecture of Wazuh

Wazuh follows a distributed architecture consisting of the following components: 

1. **Wazuh Manager:** The principal component responsible for coordinating data collection, analysis, and response actions. The Wazuh Manager aggregates security event data from agents and forwards it to the Elasticsearch database for storage and analysis.
2. **Wazuh Agents:** Lightweight software installed on monitored endpoints to collect security-relevant data, including logs, system events, and file integrity information. Agents analyze local events and report findings to the Wazuh Manger for centralized monitoring and analysis.
3. **Elasticsearch:** The scalable, distributed search and analytics engine used by Wazuh for storing and indexing security event data. Elasticsearch enables fast and efficient searching, querying, and visualization of security-related information. 
4. **Kibana:** The web-based user interface provided by Wazuh for data visualization, dashboards, and reporting. Kibana allows security analysts to explore and analyze security event data, identify trends, and respond to incidents effectively.

---

## Setup

Transitioning to setting up and configuring Wazuh entails several crucial steps. Initially, one installs the Wazuh manager on a central server, establishing the foundation for security event aggregation and analysis. Subsequently, Wazuh agents are deployed across endpoints, facilitating the collection of pertinent security data. Configuration of the Wazuh Manager ensues, orchestrating its communication with Elasticsearch for efficient data storage and retrieval, and with Kibana for intuitive data visualization. 

Finally, customizations of Wazuh’s configuration files allows organizations to fine-tune the platform to their unique security requirements, defining rulesets, thresholds, and alerting mechanisms tailored to their specific environment and risk profile. 

[The Wazuh Documentation](https://documentation.wazuh.com/current/getting-started/index.html) is quite extensive, but we will focus on the beforementioned steps, starting with the installation of the Wazuh manager. 

**While Wazuh Manager can be operated from Windows, it is recommended to be installed on a Linux system**. For our purposes we will be using [Ubuntu 22.04](https://ubuntu.com/download/desktop) being hosted on [VMware Workstation](https://www.vmware.com/products/workstation-pro.html). 

1. Download and run Wazuh installation (sudo privileges required)
    
    ```bash
    curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
    ```
    
2. A successful installation will output the following: 
    1. Note that password will vary
    
    ```bash
    18/03/2024 17:39:26 INFO: --- Summary ---
    18/03/2024 17:39:26 INFO: You can access the web interface https://<wazuh-dashboard-ip>:443
        User: admin
        Password: <PASSWORD>
    18/03/2024 17:39:26 INFO: --- Dependencies ----
    18/03/2024 17:39:26 INFO: Removing gawk.
    18/03/2024 17:39:28 INFO: Installation finished.
    
    ```
    
3. Wazuh Dashboard can now be accessed by entering the device IP into your preferred internet browser, followed by entering the corresponding Username and Password displayed in the previous step

**Next, we can start deploying Wazuh Agents to the devices we want to monitor**. In this documentation, we will be using Ubuntu as an example, but Wazuh Agent is deployable across various operating systems. This can be done directly through the Wazuh Manager Dashboard or through the command line. The Dashboard method is more streamlined and straightforward: 

1. Enter the Add Agent section by clicking on the warning displayed: 
    
    ![Untitled](Wazuh%20-%20EDR%2047b33b0490e942dcbf75a075d984c96b/Untitled.png)
    
2. Pick corresponding operating system:
    
    ![Untitled](Wazuh%20-%20EDR%2047b33b0490e942dcbf75a075d984c96b/Untitled%201.png)
    
3. Input IP address of the Wazuh Manager device (your IP will vary): 

![Untitled](Wazuh%20-%20EDR%2047b33b0490e942dcbf75a075d984c96b/Untitled%202.png)

1. Assign an agent name that describes the device and, if need be, assign the device to a existing group:

![Untitled](Wazuh%20-%20EDR%2047b33b0490e942dcbf75a075d984c96b/Untitled%203.png)

1. Run the following commands to download and install the agent 
    1. Substitute the appropriate ‘Wazuh Manager IP’ and ‘Wazuh Agent Name’

```bash
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.3-1_amd64.deb && sudo WAZUH_MANAGER='<WAZUH_MANAGER_IP>' WAZUH_AGENT_NAME='<WAZUH_AGENT_NAME>' dpkg -i ./wazuh-agent_4.7.3-1_amd64.deb
```

1. Run the following commands to start the agent: 

```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

The agents tab in the Wazuh dashboard should now display the connected Wazuh agent device: 

![Untitled](Wazuh%20-%20EDR%2047b33b0490e942dcbf75a075d984c96b/Untitled%204.png)

With the installation of Wazuh Agents and the setup of the manager now complete, the foundation for robust security monitoring is established. However, the journey does not end here. By delving deeper into Wazuh’s configuration files, we can unlock additional capabilities and tailor the platform to meet specific organizational needs. These modifications might include fine-tune detection rules, adjusting alert thresh hold, implementing custom correlation logic, or integrating additional data sources for enhanced visibility. Through ongoing refinement and optimization Wazuh evolves from a mere security tool to a tailored solution that aligns seamlessly with organizational security objectives.

---

## Configuration

The [Wazuh Proof of Concept guide](https://documentation.wazuh.com/current/proof-of-concept-guide/index.html) offers an extensive exploration into the capabilities offered, such as using the [File integrity monitoring](https://documentation.wazuh.com/current/proof-of-concept-guide/poc-file-integrity-monitoring.html) solution, [integrating VirusTotal to detect and remove malware](https://documentation.wazuh.com/current/proof-of-concept-guide/audit-commands-run-by-user.html), and [monitoring execution of malicious commands](https://documentation.wazuh.com/current/proof-of-concept-guide/audit-commands-run-by-user.html). 

### File Integrity Monitoring

Activating file integrity monitoring on Wazuh is essential for detecting unauthorized changes to a critical system files and configurations in real-time, enabling early detection of security breaches. By continuously monitoring file integrity, Wazuh can identify and alert suspicious activities, helping organizations respond promptly to potential security incidents and mitigate risks. FIM also plays a crucial role in compliance efforts, ensuring the integrity of sensitive data and facilitating adherence to regulatory requirements. 

To do so, modifications must be made to the Ubuntu endpoint configuration files. This file can be found in **`/var/ossec/etc/ossec.conf`** and opened with your preferred text editor. Near line 97 under the File integrity monitoring section, we can add directories for monitoring within the **`<syscheck>`** block: 

```bash
<directories check_all="yes" report_changes="yes" realtime="yes">/root</directories>
```

- **Check_all:** Specifies if all subdirectories within the specified directory should be monitored for changes
- **Report_changes:** Specifies whether Wazuh should generate alerts when changes are detected within the monitored directories
- **Realtime:** Specifies whether changes should be monitored in real-time

Once we have added the appropriate directories and attribute modifications, we must restart the Wazuh agent to apply the changes: 

```bash
sudo systemctl restart wazuh-agent
```

[Now we can test our FIM configurations.](https://www.notion.so/Wazuh-EDR-47b33b0490e942dcbf75a075d984c96b?pvs=21)

### VirusTotal Integration

Integrating VirusTotal with Wazuh amplifies the security monitoring capabilities by enriching threat detection with extensive intelligence from VirusTotal’s vast database of malware signatures and indicators of compromise. This integration allows for automated verification of hashes, URLs, domains, and IP addresses against VirusTotal repository, offering real-time alerts on potential threats. Consequently, organizations benefit from a heightened awareness and rapid response capability, significantly reducing the windows of opportunity for malicious actors to exploit vulnerabilities or breach systems. 

We can use Wazuh’s file integrity monitoring modules to monitor directories for changes while having the VirusTotal API to scan the files in said directory. Even still, we can configure Wazuh to trigger a response script to remove files that are deemed malicious by VirusTotal. 

To enable this integration, we must modify configuration files on both the Wazuh Server and the Wazuh Agent Endpoint. 

### Wazuh Agent

First, we must ensure that the File integrity monitoring system is not disabled within the Wazuh Agent configurations:

```bash
<disabled>no</disabled>
```

![Untitled](Wazuh%20-%20EDR%2047b33b0490e942dcbf75a075d984c96b/Untitled%205.png)

Next, we can add a directory that we want to be monitored, which in this case, will be the **`/root`** directory: 

```bash
<directories realtime="yes">/root</directories>
```

![Untitled](Wazuh%20-%20EDR%2047b33b0490e942dcbf75a075d984c96b/Untitled%206.png)

Now we will install a utility that will process JSON input from an active response script we will be implementing for this integration: 

```bash
sudo apt update
sudo apt -y install jq
```

Once this utility is installed, we can create a file that will be used as the active response script. This script should be made in the **`/var/ossec/active-response/bin/ directory`**. 

```bash
# Create file in corresponding directory
	nano -l /var/ossec/active-response/bin/remove-threat.sh

# Add the following to said file:

#!/bin/bash

LOCAL=`dirname $0`;
cd $LOCAL
cd ../

PWD=`pwd`

read INPUT_JSON
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.data.virustotal.source.file)
COMMAND=$(echo $INPUT_JSON | jq -r .command)
LOG_FILE="${PWD}/../logs/active-responses.log"

#------------------------ Analyze command -------------------------#
if [ ${COMMAND} = "add" ]
then
 # Send control message to execd
 printf '{"version":1,"origin":{"name":"remove-threat","module":"active-response"},"command":"check_keys", "parameters":{"keys":[]}}\n'

 read RESPONSE
 COMMAND2=$(echo $RESPONSE | jq -r .command)
 if [ ${COMMAND2} != "continue" ]
 then
  echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Remove threat active response aborted" >> ${LOG_FILE}
  exit 0;
 fi
fi

# Removing file
rm -f $FILENAME
if [ $? -eq 0 ]; then
 echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Successfully removed threat" >> ${LOG_FILE}
else
 echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Error removing threat" >> ${LOG_FILE}
fi

exit 0;
```

Now we must change the file ownership and permissions to the file to ensure it runs properly: 

```bash
sudo chmod 750 /var/ossec/active-response/bin/remove-threat.sh
sudo chown root:wazuh /var/ossec/active-response/bin/remove-threat.sh
```

And then we restart the Wazuh agent to apply the changes and move over to the Wazuh Server: 

```bash
sudo systemctl restart wazuh-agent
```

### Wazuh Server

The first change we must make on the Wazuh server is to adjust the Wazuh rules so that they alert about changes in the corresponding directory detected by FIM scans:

```bash
# Open following rules file

nano -l /var/ossec/etc/rules/local_rules.xml

# Add the following to the file: 

<group name="syscheck,pci_dss_11.5,nist_800_53_SI.7,">
    <!-- Rules for Linux systems -->
    <rule id="100200" level="7">
        <if_sid>550</if_sid>
        <field name="file">/root</field>
        <description>File modified in /root directory.</description>
    </rule>
    <rule id="100201" level="7">
        <if_sid>554</if_sid>
        <field name="file">/root</field>
        <description>File added to /root directory.</description>
    </rule>
</group>
```

Now we add the following to the ossec.conf file to enable the VirusTotal Integration:

```bash
# Open following file: 

	nano -l /var/ossec/etc/ossec.conf
	
# Add the following:

<ossec_config>
  <integration>
    <name>virustotal</name>
    <api_key><YOUR_VIRUS_TOTAL_API_KEY></api_key> <!-- Replace with your VirusTotal API key -->
    <rule_id>100200,100201</rule_id>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
```

<aside>
💡 Note that you must have a [VirusTotal account](https://www.virustotal.com/gui/sign-in) to have an API key for this section.

</aside>

We can also add another block of code to the same ossec.conf file to enable active response by triggering the remove-threat.sh script we created earlier.   

```bash
<ossec_config>
  <command>
    <name>remove-threat</name>
    <executable>remove-threat.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>remove-threat</command>
    <location>local</location>
    <rules_id>87105</rules_id>
  </active-response>
</ossec_config>
```

Next, we can add another block of code to the local_rules.xml file to alert about the active response results: 

```bash
# Open following file: 

nano -l /var/ossec/etc/rules/local_rules.xml

# Add the following: 

<group name="virustotal,">
  <rule id="100092" level="12">
    <if_sid>657</if_sid>
    <match>Successfully removed threat</match>
    <description>$(parameters.program) removed threat located at $(parameters.alert.data.virustotal.source.file)</description>
  </rule>

  <rule id="100093" level="12">
    <if_sid>657</if_sid>
    <match>Error removing threat</match>
    <description>Error removing threat located at $(parameters.alert.data.virustotal.source.file)</description>
  </rule>
</group>
```

Finally, we can restart the Wazuh Manager to apply the modified configurations: 

```bash
sudo systemctl restart wazuh-manager
```

[Now we can perform some simple tests to ensure VirusTotal integration.](https://www.notion.so/Wazuh-EDR-47b33b0490e942dcbf75a075d984c96b?pvs=21) 

### Monitoring execution of malicious commands

Combining Auditd with Wazuh enhances security monitoring by providing insight into the execution of potentially malicious commands on the system. Auditd, the Linux auditing framework, records detailed information about system calls and user actions. By integrating Auditd logs with Wazuh, organizations can correlate these events with other security data, enabling proactive detection and response to suspicious activities. This synergy enables Wazuh to alert on anomalous command executions, empowering organizations to swiftly identify and mitigate security threats, thereby bolstering overall cybersecurity defenses. 

### Wazuh Endpoint

Auditd can be installed and started on the Linux endpoint with the following commands: 

```bash
sudo apt -y install auditd
sudo systemctl start auditd
sudo systemctl enable auditd
```

We can then apply certain audit rules to monitor for a specific user ID, group ID, and system architecture. Anything that might trigger these rules is then classified to a certain label to be used by Wazuh. 

```bash
echo "-a exit,always -F auid=1000 -F egid!=994 -F auid!=-1 -F arch=b32 -S execve -k audit-wazuh-c" >> /etc/audit/audit.rules
echo "-a exit,always -F auid=1000 -F egid!=994 -F auid!=-1 -F arch=b64 -S execve -k audit-wazuh-c" >> /etc/audit/audit.rules
```

Next, we reload the rules: 

```bash
sudo auditctl -R /etc/audit/audit.rules
sudo auditctl -l
```

And then we confirm that they are established by noting if the applied rules are in the output of the prior command: 

![Untitled](Wazuh%20-%20EDR%2047b33b0490e942dcbf75a075d984c96b/Untitled%207.png)

Once we have confirmed the Auditd rule, we modify the **`/var/ossec/etc/ossec.conf`** file of the agent so that the Wazuh agent can read the audit logs file. This can be done with the following code block:

```bash
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

Now we can restart the Wazuh agent: 

```bash
sudo systemctl restart wazuh-agent
```

### Wazuh Server

On the server we must create A CDB list of potentially malicious programs and rules that can be used to detect the execution of the programs in the list. This can be done by adding a CDB list that contains suspicious programs within the **`/var/ossec/etc/lists`** directory:

```bash
# create file
nano /var/ossec/etc/lists/suspicious-programs

# add the following to the created file:
ncat:yellow
nc:red
tcpdump:orange
```

We can then add this list to the rule set section of the Wazuh server in the **`/var/ossec/etc/ossec.conf`** file: 

```bash
# open ossec.conf file
nano -l /var/ossec/etc/ossec.conf

# add the following: 
<list>etc/lists/suspicious-programs</list>
```

Next, we add a rule to the **`/var/ossec/etc/rules/local_rules.xml`** to be triggered when a program is executed: 

```bash
<group name="audit">
  <rule id="100210" level="12">
      <if_sid>80792</if_sid>
  <list field="audit.command" lookup="match_key_value" check_value="red">etc/lists/suspicious-programs</list>
    <description>Audit: Highly Suspicious Command executed: $(audit.exe)</description>
      <group>audit_command,</group>
  </rule>
</group>
```

[Adding this final modification leads us to performing a test.](https://www.notion.so/Wazuh-EDR-47b33b0490e942dcbf75a075d984c96b?pvs=21) 

---

## Use Cases and Demonstration

### File Integrity Monitoring

To test our FIM configurations we can simply create a text file in the monitored directory, add content to the file, and then delete the text file. This should create security events within the Wazuh dashboard which we can then visualize. 

The directory that we are currently monitoring is the **`/root`** directory, so we can create a simple file within this directory:

```bash
#Sudo privilege will be needed to alter the root directory
sudo su

#Change into root directory
cd /root

#Create file with preferred text editor
nano testfile.txt

#Modify the file in some way, i.e.: add random strings to it and save the file

#Remove the file
rm testfile.txt
```

Upon completing the setup, we transition to exploring the capabilities of Wazuh via the Manager Dashboard. Navigate to the “Agent” tab, where you can select the desired agent to view a comprehensive overview. This overview presents various categories, including events over time, MITRE ATTACK relevant events, and Security Configuration Assessment, among others. Our focus shifts to the Integrity Monitoring category, accessible either through its pane or by selecting the tab labeled “Integrity monitoring” near the top of the page. Here, we’re greeted with a detailed visualization of integrity monitoring events. For those seeking a deeper dive into these events, the “Events” tab offers a granular look, allowing us to scrutinize the specific incidents closely.   

Here we can note the following events: 

![Untitled](Wazuh%20-%20EDR%2047b33b0490e942dcbf75a075d984c96b/Untitled%208.png)

Here it is possible to parse through the data by filtering it through filed names, such as “rule.id”

with the corresponding ID number that describes the actions that we just took: 

- **550:** Integrity checksum changed
- **553:** File Deletion
- **554:** File added to the system

Once we have decided on which rule IDs to focus on, we can add a filter that focuses on relevant files: 

![Untitled](Wazuh%20-%20EDR%2047b33b0490e942dcbf75a075d984c96b/Untitled%209.png)

As we can see, our File Integrity Monitoring system displays the actions we undertook. It shows the creation of the file, the modification of the file, and the deletion of the file.

Leveraging this initial setup as a template, we can effortlessly scale our file integrity monitoring efforts across additional directories vital to an organization, ensuring comprehensive coverage. By customizing the monitoring rules to align with specific business needs, we can extend protection to encompass a wider array of sensitive or critical files and directories. This scalable approach empowers organizations to maintain stringent file integrity checks, adapting seamlessly to evolving security requirements and business objectives. 

### VirusTotal Integration

To verify the efficacy of the VirusTotal integration with Wazuh, utilizing an [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) provides a safe and effective method. The EICAR test file is a standardized string designed to be detected as a virus by antivirus engines, yet it is harmless. By introducing this file into the system monitored by Wazuh, and observing the alerts generated through the VirusTotal integration, organizations can confidently assess the real-time detection capabilities and ensure that the integration is functioning as intended. 

This file can be downloaded from the [website directly](https://www.eicar.org/download-anti-malware-testfile/), or we can also use the curl command to download the EICAR file to the desired directory:  

```bash
# curl: used to transfer data from or to a server
# -Lo: -L follows redirects and -o specifies the output file

sudo curl -Lo /root/eicar.com https://secure.eicar.org/eicar.com 
&& sudo ls -lah /root/eicar.com

# ls -lah: lists information about the downloaded file
```

We can then head over to our Wazuh Dashboard, select the appropriate agent, and then open the security events tab to analyze any alerts: 

![Untitled](Wazuh%20-%20EDR%2047b33b0490e942dcbf75a075d984c96b/Untitled%2010.png)

As we can see, there are several events which note the addition of the file in /root directory, there after followed by a VirusTotal alert and active response which results in the file being deleted. If we want to isolate these events according to rule ID, we can add the following filter: 

![Untitled](Wazuh%20-%20EDR%2047b33b0490e942dcbf75a075d984c96b/Untitled%2011.png)

 

This filter parses through the security events for the following rules: 

- **553:** File deleted
- **100092:** Active response alert (which we added in the local_rules.xml file)
- **87105:** VirusTotal alert
- **100201:** System check according to specified rules (Such as the addition of the /root directory to be monitored for file integrity)

### Monitoring Execution of Malicious Commands

One such use case of this configuration setup can be to monitor the execution of a program that is within our created CDB list. In this case, we will try to see if Wazuh notices the execution of Netcat in the Linux Endpoint. 

To do so, we can install netcat if necessary: 

```bash
sudo apt -y install netcat
```

And then we can pass the Netcat option through the command line: 

```bash
nc
```

Even by simply passing the base **`nc`** command, Wazuh generates an event that corresponds to our Auditd rule configurations: 

![Untitled](Wazuh%20-%20EDR%2047b33b0490e942dcbf75a075d984c96b/Untitled%2012.png)

---

## Performance Evaluation

Wazuh is celebrated for its effectiveness and efficiency as an open-source platform for threat detection, incident response, and compliance monitoring. Its flexibility and adaptability stem from a robust community-driven development process that continually enhances the platform’s capabilities. Wazuh integrates seamlessly with a wide range of third-party services and tools, such as our example covering VirusTotal, thereby extending its functionality beyond its core features. 

Moreover, the platform offers comprehensive security measures across various fronts: log data collection, vulnerability detection, container security, system inventory, and more, ensuring a broad coverage of security needs. It supports a wide array of use cases, from file integrity monitoring to detecting brute-force attacks, making it a versatile tool for organizations of all sizes. As highlighted by our use cases section, the [Proof-of-Concept](https://documentation.wazuh.com/current/proof-of-concept-guide/index.html) guide in Wazuh’s documentation illustrates its capability to tailor security measures to specific organizational needs, demonstrating its flexibility and power in real-world scenarios. 

What makes Wazuh standout is its approach to cybersecurity, which is centered around providing unified protection for both endpoints and cloud workloads, blending traditionally separate functions into a cohesive security strategy. This holistic security approach is not only cost-effective but also simplifies the management of security measures, allowing organizations to deploy a comprehensive security platform without the complexities typically associated with such a wide-ranging solution. 

---

## Conclusions and Recommendations

In conclusion, Wazuh stands out as a comprehensive cybersecurity solution, adept at meeting modern cybersecurity challenges through its open-source, flexible framework. This platform excels in unifying endpoint protection, cloud security, incident response, and compliance management, simplifying the cybersecurity infrastructure for organizations of all sizes. 

For successful implementation, it is recommended to start with an assessment of specific security requirements and gradually integrating Wazuh to ensure it aligns with the organization’s existing environment. Engaging with the Wazuh community and leveraging its integrations can significantly enhance the platform’s effectiveness and provide a richer security posture.

By prioritizing continuous monitoring and regular updates, organizations can harness Wazuh's full potential to safeguard against threats and maintain compliance with evolving regulations. Ultimately, Wazuh's blend of comprehensive capabilities, community support, and adaptability positions it as an asset for robust cybersecurity defense strategies.

---

## **References**

For further reading, it is recommended to explore the following: 

- [The official Wazuh documentation](https://documentation.wazuh.com/current/index.html)
- [The Wazuh Blog](https://wazuh.com/blog/)
- [Official Wazuh training courses](https://wazuh.com/services/training-courses/#services-training-courses)
- [Various Wazuh communities, such as slack, discord, etc.](https://wazuh.com/community/)

Additionally, the use of Wazuh has sparked my interest in terms of how to leverage the security configuration assessment feature to harden systems. The following two links tackle this very exploration, one noting the benchmark failures on an Ubuntu system, while the other notes remediation steps:

[CIS Ubuntu Linux 22.04 LTS Benchmark Failures](https://www.notion.so/a2d09833e32d4d11af155c8d967e0d34?pvs=21)

[Remediation Steps - Linux](https://www.notion.so/Remediation-Steps-Linux-af23e7335edf4487bfbe177d454dfba7?pvs=21)

---

Feel free to check out my [other projects](https://randyramirez95.github.io/landing.html) for more detailed guides!