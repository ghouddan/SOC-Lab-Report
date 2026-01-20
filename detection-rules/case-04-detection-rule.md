# Sigma Rule Format  
```
title: Kerberoasting Attack Detection  
id: 934632c0-10f0-418a-91eb-18df492b7c19
status: experimental  
description: Detects abnormal Kerberos service ticket request patterns indicative of Kerberoasting
author: SOC Detection Lab  
date: 2025/01/20   
references:  
    - https://attack.mitre.org/techniques/T1558/003/
tags:  
    - attack.credential_access
    - attack.T11558.003
logsource:  
    product: windows  
    service: security  
detection:  
    Selection:
        EventID: 4769  
        TicketEncryptionType: '0x17'
        ServiceName|endswith: '$'
    Filter_exclude:
            ServiceName|Startswith:
                - 'krbtgt'
                - '$'
    condition: Selection and not Filter_exclude
false positives:  
    - Legitimate service discovery scripts
    - Misconfigured services
    - Administrative troubleshooting
level: high  
fields:
    - SubjectUserName
    - IpAddress
    - WorkstationName
    - TargetUserName
    - TicketEncryptionType
    - ServiceName
    - TicketOptions
``` 