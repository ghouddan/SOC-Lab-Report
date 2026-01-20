# Kerberoasting Attack Detection 

## Detection Objective   
Detect abnormal Kerberos service ticket requests indicative of service enumeration or credential extraction.

## Attack Chain Recap   
Multiple events of Kerberos service ticket requests (TGS)  within a short time window, issued by a single domain user account targeting several unrelated service accounts (SPN) while relying on a single source IP address.

## Detection Signal     
**Signal 1: Multiple Kerberos service tickets requests**  
Event Id 4769 was observed several times on the domain control machine. This indicates a Kerberos service ticket (TGS) request targeting multiple unrelated service accounts issued by a single domain user account from the same source IP address. 

**Correlation**   
Multiple Kerberos services within ticket requests within a short time window, targeting multiple unrelated service accounts and using a single domain user account, deviate from typical user authentication behavior.

## Detection Gap    
Kerberoasting activity does not inherently generate a malicious or failed authentication event. Event ID 4769 alone does not confirm credential compromise, as ticket extraction and offline password cracking occur outside of the monitored environment. Detection therefore rely o behavior baselining  and anomaly detection rather than deterministic indicators. 

## False Positive    
- Legitimate applications or scripts performing service discovery
- Administrative troubleshooting or testing of service connectivity
- Misconfigured services repeatedly requesting tickets
