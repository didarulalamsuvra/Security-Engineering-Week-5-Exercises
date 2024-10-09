# Security-Engineering-Week-5-Exercises

TASK 1 


Intrusive application practices: Some mobile applications may collect excessive personal or engage in unauthorized access, compromising user privacy and organizational security​.

Account credential theft through phishing: Phishing attacks trick users into revealing login credentials, such as usernames and passwords, often through deceptive emails, which allow unauthorized access to accounts​.

Outdated phones: Devices that run older, unpatched operating systems or applications are vulnerable to known security exploits, increasing the risk of compromise through malware attacks​.

Sensitive data transmissions: Unencrypted transmission of sensitive data can lead to interception by malicious actors.

Brute-force attacks to unlock a phone: Attackers may attempt to guess a phone’s PIN or password through brute-force methods, gaining unauthorized access to the device ​.

Application credential storage vulnerability: Insecure storage of credentials within applications, such as storing passwords in plain text, can be exploited by attackers to access systems and sensitive data.

Unmanaged device protection: Devices not managed by the organization may lack adequate security controls, leaving them vulnerable to attacks and increasing the risk of unauthorized access to data.

Lost or stolen data protection: When devices containing sensitive data are lost, without sufficient protection, the data could be accessed by unauthorized individuals​.

Protecting enterprise data from being inadvertently backed up to a cloud service: Data stored on a BYOD device could be inadvertently backed up to insecure cloud services, where it might be exposed to unauthorized access​.


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
ZombieLoad exploits the fill buffer in Intel CPUs to read data that is being processed by other applications. This attack leaks sensitive information in real time.

Target Systems: Primarily affects Intel CPUs.  

Mitigation: Microcode updates and operating system patches are required. In some cases, disabling hyper-threading reduces the risk.



TASK 3 :

