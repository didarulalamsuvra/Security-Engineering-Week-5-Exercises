# Security-Engineering-Week-5-Exercises

TASK 1 


Intrusive application practices: Some mobile applications may collect excessive personal or engage in unauthorized access, compromising user privacy and organizational security.

Account credential theft through phishing: Phishing attacks trick users into revealing login credentials, such as usernames and passwords, often through deceptive emails, which allow unauthorized access to accounts.

Outdated phones: Devices that run older, unpatched operating systems or applications are vulnerable to known security exploits, increasing the risk of compromise through malware attacks.

Sensitive data transmissions: Unencrypted transmission of sensitive data can lead to interception by malicious actors.

Brute-force attacks to unlock a phone: Attackers may attempt to guess a phone’s PIN or password through brute-force methods, gaining unauthorized access to the device​.

Application credential storage vulnerability: Insecure storage of credentials within applications, such as storing passwords in plain text, can be exploited by attackers to access systems and sensitive data.

Unmanaged device protection: Devices not managed by the organization may lack adequate security controls, leaving them vulnerable to attacks and increasing the risk of unauthorized access to data.

Lost or stolen data protection: When devices containing sensitive data are lost, without sufficient protection, the data could be accessed by unauthorized individuals.

Protecting enterprise data from being inadvertently backed up to a cloud service: Data stored on a BYOD device could be inadvertently backed up to insecure cloud services, where it might be exposed to unauthorized access.


TASK 2 : 

Here are three CPU side-channel vulnerabilities, their mechanisms, target systems, and mitigations:

1. Spectre:  
Spectre tricks the CPU into speculative execution, which involves predicting which instructions to execute before their outcomes are certain. By manipulating speculative branches, attackers can cause the CPU to access sensitive data in memory and observe side effects to infer the leaked data.  

Target Systems: It affects nearly all modern processors, including Intel, AMD, and ARM, made since 1995.  

Mitigation: Software patches, such as disabling certain speculative optimizations, and hardware-based microcode updates can mitigate Spectre. Memory isolation techniques also help.

2. Meltdown:  
Meltdown exploits out-of-order execution. It allows attackers to bypass the standard memory isolation mechanisms. It enables unauthorized reading of kernel memory from user space, exposing sensitive data.  

Target Systems: Mostly impacts Intel processors but also affects some ARM and IBM CPUs.  

Mitigation: Kernel Page Table Isolation is a key mitigation. Microcode updates and software patches also mitigate the vulnerability.

3. ZombieLoad:  
ZombieLoad exploits the fill buffer in Intel CPUs to read data being processed by other applications. This attack leaks sensitive information in real-time.

Target Systems: Primarily affects Intel CPUs.  

Mitigation: Microcode updates and operating system patches are required. In some cases, disabling hyper-threading reduces the risk.



TASK 3:


Malware and Viruses
Malware can steal personal data, damage files, or take over the system for malicious purposes.
Windows uses Windows Defender to scan for and block malware. Regular system updates and the SmartScreen filter also help prevent known threats.
Function: Windows OS  with optional external antivirus tools for layered protection.
Exploiting Software Vulnerabilities
Exploiting unpatched software vulnerabilities can lead to unauthorized system access, data theft, or control of the OS.
Windows includes 'Windows Update' to patch vulnerabilities regularly. Windows Security also ensures compliance with patches.
Function: The OS manages updates, while additional tools can be used externally.

Phishing and Social Engineering
Phishing can trick users into revealing sensitive information like passwords or financial data.
Windows Defender’s SmartScreen blocks malicious websites and links. Email clients include phishing detection mechanisms.
Function: OS-integrated features, especially within web browsers and email clients.

Drive-by Downloads
These downloads happen without consent, potentially delivering malware when visiting compromised websites.
Windows Defender SmartScreen prevents malicious downloads, and Microsoft Edge isolates browser processes to reduce risks.
Function: OS-level security through browser integration and Defender.

Zero-Day Exploits
Zero-day vulnerabilities are unknown weaknesses that attackers can exploit before patches are released.
Regular updates through Windows Update, with additional real-time protection from Defender to block suspicious behaviour.
Function: OS-based updates and real-time protection.

USB/Removable Media Attacks
Malware can spread via infected USB drives, leading to unauthorized access, data loss, or system compromise.
BitLocker encryption and Windows Defender can scan media, while administrators can disable autorun to prevent the automatic execution of malicious files.
Function: OS-level tools and Group Policy settings.

Password Cracking
Attackers can use brute-force methods to crack passwords, leading to unauthorized account access.
Windows enforces strong password policies, two-factor authentication and Windows Hello for biometric authentication.
Function: OS-level features like 2FA and password policies.

TASK 4 :

Log files are crucial for maintaining, troubleshooting, and understanding the behaviour of systems and applications. 

Application Logs-
Information Saved:
Application-specific events, User activity within the application, and Transaction details.
Examples: Logs from web servers, database systems, and user applications.

Event Logs-
Information Saved:
System events, including system start-up/shutdown, user logins, and security-related events.Application errors, warnings, and informational messages.
Examples: Security events, application errors, and system warnings.

Service Logs-
Information Saved:
Status of services, Health and performance metrics, Errors and warnings generated by services.
Examples: Logs from background services like web servers, database services, etc.

System Logs-
Information Saved:
Hardware-related events, Kernel events, operating system errors, System resource usage and performance data.
Examples: Logs generated by the operating system itself regarding system-level issues.

Windows
Application Logs: Located in C:\Program Files\<Application>\Logs or via Event Viewer under Windows Logs > Application.
Event Logs: Stored in the Event Viewer under Windows Logs (Security, System, Application).
Service Logs: Found in Event Viewer under Windows Logs > System or specific application directories.
System Logs: Located in the Event Viewer under Windows Logs > System.

macOS
Application Logs: Found in ~/Library/Logs or /Library/Logs.
Event Logs: System logs can be viewed using the Console app or located in /var/log/system.log.
Service Logs: Service logs can be accessed through the Console app or found in /var/log/<service-name>.log.
System Logs: Located in /var/log/system.log and accessible via the Console app.

Linux 
Application Logs: Commonly located in /var/log/<application>.log.
Event Logs: Most system events are recorded in /var/log/syslog or /var/log/messages (depending on the distribution).
Service Logs: Located in /var/log/<service-name>.log or via the journalctl command for systemd services.
System Logs: Generally stored in /var/log/syslog or /var/log/kern.log.

Application Logs
Threats:
Unauthorized access attempts.
Application errors indicate potential attacks.
Performance issues that may indicate denial of service attacks.

Event Logs
Threats:
Multiple failed login attempts suggest brute force attacks.
Unusual user behaviour patterns.
System crashes or unexpected shutdowns indicate possible malware activity.

Service Logs
Threats:
Service failures that may indicate targeted attacks.
Unauthorized access or tampering with services.
Performance degradation or irregular service behaviour.

System Logs
Threats:
Kernel panics or hardware failures suggest potential physical security breaches.
Resource usage spikes that may indicate a malware infection or a DoS attack.
Suspicious changes in system files indicate unauthorized modifications.

Monitoring Logs on a Personal Computer:
Methods for Monitoring Logs
Built-in Tools:
Windows: Use Event Viewer to analyze application, security, and system logs.
macOS: Utilize the Console app for viewing all system logs and application logs.
Linux: Use the journalctl command for systemd logs or view logs in /var/log/ directory.
Third-party Tools:
Log management software: Tools like Splunk, Loggly, or ELK Stack can aggregate and analyze log files.
Intrusion Detection Systems: Software like OSSEC can monitor log files for suspicious activity and send alerts.
Scripts and Automation:
Create scripts to periodically check log files for specific entries  and send alerts.
Use cron jobs  or Task Scheduler  to automate log monitoring tasks.

Sources
https://learn.microsoft.com/en-us/windows/win32/eventlog/event-logging
https://support.apple.com/guide/console/welcome/mac
https://www.linux.com/training-tutorials/linux-documentation-project/



