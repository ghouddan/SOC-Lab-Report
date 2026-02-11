# RDP Brute Force Attack Detection 

## Detection Objective 
	Detect external brute force attempts targeting (3389/TCP) against a domain-joined host, leading to credential compromise and remote interactive access.
## Attack Chain Recap 
An external IP address initiated multiple connections to TCP port 3389 on a domain-joined machine.
This was followed by multiple failed authentication attempts (Event ID 4625, logon Type 3) using different user accounts from the same source IP.
Subsequently, a successful authentication occurred from the same source IP.
If the attacker established a desktop session, a 4624 logon type 10 was recorded on one of the previous targeted accounts.

## Detection Signals 
**Signal 1: RDP Port Exposure**       
Event ID 5156 (Windows Filtering Platform) indicates permitted inbound TCP traffic on port 3389 from an external source IP address.    
**Signal 2: Network Connection Telemetry**    
Sysmon Event ID 3 shows inbound network connection activity targeting port 3389.    
**Signal 3: Brute Force Pattern**    
Multiple event ID 4625 with:     
- Logon type 3 (if NLA is enabled)    
- Same source IP    
- multiple distinctive usernames    
- Within a fixed interval of time
**Signal 4: Credential Compromise**    
Event ID 4624 from the same source IP.    
- With logon type 3, it indicates a successful credential validation (NAL phase)
- With logon type 10 confirm interactive RDP session establishment
## Detection Gap 
- No visibility into the originating process on the attacker side (as expected).
- Limited payload visibility in the Sysmon Event ID 3.
- If NLA is disabled, log pattern shift (type 10 failure instead of type 3). Detection login must adapt.

## False Positive 
- Legitimate remote admins mistyping passwords repeatedly.
- Identity provisioning scripts validating multiple accounts.
- VPN gateway IP used by multiple users causing shared source IP.
