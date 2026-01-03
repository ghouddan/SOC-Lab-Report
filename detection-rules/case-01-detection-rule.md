
# Sigma Rule Format  
```
title: Remote Command Execution via Service Creation  
id: d18818be-175e-42bc-b93f-23ad48a071c2  
status: experimental  
description: Detects service creation within 5 minutes of network logon by non-admin account  
author: SOC Detection Lab  
date: 2025/01/03   
references:  
    - https://attack.mitre.org/techniques/T1543/003/  
tags:  
    - attack.lateral_movement  
    - attack.persistence  
    - attack.t1543.003  
logsource:  
    product: windows  
    service: security  
detection:  
    network_logon:  
        EventID: 4624  
        LogonType: 3  
        TargetUserName|not_contains:  
            - '$'  
            - 'SYSTEM'  
            - 'admin'  
            - 'svc_'  
    service_creation:  
        EventID: 7045  
        ServiceAccount: 'LocalSystem'  
    timeframe: 5m  
    condition: network_logon | near service_creation  
falsepositives:  
    - SCCM/patch management  
    - Software deployment tools  
    - Authorized maintenance windows  
level: high  
``` 