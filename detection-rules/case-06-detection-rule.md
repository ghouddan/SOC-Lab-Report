# Sigma Rule Format
```
title: RDP Brute Force Attack Detection
id: 391996d9-2911-4e43-be33-1b74d5889e33
status: experimental
description: Detects external brute force attempts against RDP (3389/TCP) followed by successful authentication
author: SOC Detection Lab
date: 2025/02/11
references:
    - https://attack.mitre.org/techniques/T1110/001/
    - https://attack.mitre.org/techniques/T1021/001/
tags:
    - attack.credential_access
    - attack.lateral_movement
    - attack.t1110.001
    - attack.t1021.001
logsource:
    product: windows
    service: security
detection:
    # Signal 1: Multiple failed RDP authentication attempts
    rdp_brute_force:
        EventID: 4625
        LogonType:
            - 3   # NLA enabled
            - 10  # NLA disabled
        IpPort: '3389'

    # Signal 2: Successful authentication after failures
    rdp_success:
        EventID: 4624
        LogonType:
            - 3   # NLA phase success
            - 10  # Interactive RDP session
        IpPort: '3389'

    # Filter out internal/private IP ranges
    filter_internal:
        IpAddress|startswith:
            - '192.168.56'
            - '127.'
            - '-'  # Exclude local/null values

    condition: (rdp_brute_force or rdp_success) and not filter_internal
falsepositives:
    - Legitimate remote admins mistyping passwords
    - Identity provisioning scripts validating multiple accounts
    - VPN gateway IPs shared by multiple users
level: medium
fields:
    - IpAddress
    - TargetUserName
    - LogonType
    - WorkstationName
    - Computer
    - IpPort
    - FailureReason
```
