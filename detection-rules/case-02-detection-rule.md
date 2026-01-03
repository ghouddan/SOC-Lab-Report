
# Sigma Rule Format  
```
title: Remote Scheduled Task Creation via Admin Share Access  
id: 55913cb5-5e53-45af-831c-9f8749238697  
status: experimental  
description: Detects scheduled task creation within 5 minutes of administrative share access by non-admin account  
author: SOC Detection Lab  
date: 2025/01/03  
references:  
    - https://attack.mitre.org/techniques/T1053/005/  
tags:  
    - attack.persistence  
    - attack.execution  
    - attack.t1053.005  
logsource:  
    product: windows  
    service: security  
detection:  
    admin_share_access:  
        EventID: 5145  
        ShareName|contains:  
            - 'ADMIN$'  
            - 'IPC$'  
        SubjectUserName|not_contains:  
            - '$'  
            - 'SYSTEM'  
            - 'admin'  
            - 'svc_'  
    scheduled_task_creation:  
        EventID: 4698  
        SubjectUserName|not_contains:  
            - '$'  
            - 'SYSTEM'  
            - 'admin'  
            - 'svc_'  
    timeframe: 5m  
    condition: admin_share_access | near scheduled_task_creation  
falsepositives:  
    - SCCM/GPO-based task deployment  
    - IT automation scripts  
    - Authorized maintenance windows  
level: high  
```
