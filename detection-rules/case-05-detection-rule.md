# Sigma Rule Format  
```
title: credential_access - lateral movement
id: ea508ada-8b1e-4e69-8493-b4db79922cf1
status: experimental  
description: Detect suspicious activity related to network connection to the LSASS process, 
author: SOC Detection Lab  
date: 2025/01/20   
references:  
    - https://attack.mitre.org/techniques/T1003/001
    - https://attack.mitre.org/techniques/T1550/002/
tags:  
    - attack.credential_access
    - attack.lateral_movement
    - attack.T1003.001
    - attack.T1550.002
logsource:  
    product: windows  
    service: security  
detection:  
    network_connection:
        EventId: 4624
        LogonType: 3
    lsass_connection:
        EventId: 5156
        Application|endwith: '\lsass.exe'
        Direction: 'OUTBOUND'
    ntlm_authentication:
        EventId: 4624
        LongonType: 3
        Authentication_Package: 'NTLM'
    admin_share_access:
        EventId: 5140
        ShareName: 
            - 'IPC$'
            - 'ADMIN$'
            - 'C$'
    filter_dc:
        computer|contains: 'DC'
    condition: (network_connection and lsass_connection and ntlm_authentication and admin_share_access) and not filter_dc
false positives:  
    - legitimate administrative activity using NTLM for legacy systems
    - Authorized management tool accessing IPC$
level: medium  
fields:
    - IpAddress
    - WorkstationName
    - TargetUserName
    - ServiceName
    - ShareName
    - Application
    - LogonType
``` 