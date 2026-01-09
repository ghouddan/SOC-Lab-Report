# Sigma Rule Format  
```
title: Password Spraying Attack  
id: 9f4ffd7e-fc29-4ccb-81a9-b6a02f9d19fc
status: experimental  
description: Detect password spraying attempts against domain-joined hosts using network-based authentication.
author: SOC Detection Lab  
date: 2025/01/08   
references:  
    - https://attack.mitre.org/techniques/T1110/003/
tags:  
    - attack.credential-access  
    - attack.T1110.003  
logsource:  
    product: windows  
    service: security  
detection:  
    Failed Network Logon:
        EventID: 4625  
        LogonType: 3
    Credential Validation:  
        EventID: 4776
        status: '0xC0000064'
    condition: Failed Network Logon or Credential Validation
falsepositives:  
    - VPN authentication retries
    - Misconfigured application
    - Identity provisioning scripts
level: high  
fields:
    - SubjectUserName
    - IpAddress
    - WorkstationName
    - TargetUserName
    - LogonType
    - Failure Reason
``` 