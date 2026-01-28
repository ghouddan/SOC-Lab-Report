# Multi-stage credential access and lateral movement activity (Credential Dumping → Pass-the-Hash)

## Detection Objective 
    Detect suspicious authentication and system interaction patterns consistent with credential access followed by credential reuse for lateral movement.
## Timeline
    A network authentication to a domain-joined machine was followed by a permitted network activity involving the Lsass.exe process on the host. After a short time window, a second network long (type 3) occurred from the same source IP using a different account and the NTLMSSP authentication protocol, followed by administrative shared access.

## Evidence Observed

**Signal 1: Network-based authentication to a domain-joined machine**        
    Event ID 4624 indicates a successful network (type 3) authentication to a domain-joined machine, validated by the domain controller.
**Signal 2: Permitted network connection involving Lsass.exe process**   
    Event ID 5156 indicates that the Windows Filtering Platform has permitted a network connection involving the Lsass.exe process. While this does not prove memory access, network interaction involving Lsass.exe is uncommon and high-risk, and may indicate credential access-related activity when correlated with other signs.
**Signal 3: Network-based authentication to a domain-joined machine**    
   Event ID 4624 indicates a successful network logon (type 3) from the same source IP using a different account and NTLM authentication rather than Kerberos, which may indicate credential material reuse.
**Signal 4: Network-based administrative share access**    
   Event ID 5140 indicates access to the administrative share (IPC$) from the same remote source, when observed outside of the known management hosts, suggests a remote interaction with the system.
**Correlation**    
	Successful network authentication followed by LSASS-related network activity and subsequent NTLM-based authentication from the same source IP using a different account, combined with administrative share access. 
## Detection Gap 
- No visibility into the credential extraction method    
- No EDR or Sysmos telemetry to confirm memory access   
- Event ID 5156 does not conclusively prove credential dumping action.   
- The absence of event ID 4688 prevents visibility into the process creation and execution.   

## False Positive
- Legitimate administrative activity using NTLM for legacy systems 
- Authorized management tool 	accessing IPC$
- Domain control authentication involving LSASS during authentication bursts


