#Password Spraying Attack 

## Detection Objective  
Detect password spraying attempts against domain-joined hosts using network-based authentication.	

## ttack Chaine  
An attacker attempts network-based authentication against one or more domain-joined hosts using multiple distinct domain accounts over a fixed or low-frequency time interval, often from the same or a small set of source IP addresses.

## Detection Signal  

Signal 1: Multiple credential validation over a fixed time interval  
    Event ID 4776 indicates NTLM credential validation attempts performed by the domain controller on behalf of the remote authentication request.

Signal 2: Multiple failed authentication attempts separated by a fixed time interval  
    Event ID 4625 records repeated failed network-based logon attempts (Logon type 3) originating from the same source IP and targeting the same host using multiple user accounts

Correlation:  
    Multiple network-based authentication attempts from the a single or a limited set of source IP addresses, using multiple distinct user accounts against the same target host and spaced by a fixed or low-frequency time interval. 

## Detection GAP  
Limited Source Attribution  
    Event ID 4767 provides visibility into the credential validation attempts but does not include the source IP address or the originating information, limiting the attribution without the correlation to the endpoint logon events. 

    Low-and-slow password spraying attempts may evade threshold-based detection when attempts are sufficiently spaced to avoid account lockout pr alerting rules. 

## False Positive 

- VPN or identity provider retrying authentication during connectivity issues 
- Misconfigured application or services repeatedly attempting authentication 
- Identity provisioning or testing, or testing script validating multiple accounts 
