# RDP Brute Force  (Initial access)

**Alert triggered:** Inbound traffic to port 3389 from an external IP    
**MITRE ATT&CK:** T1110.003    
**Severity:** High    
**MTTR:** 15 minutes triage 1 hour 15 minutes full containment    

## Initial Triage 15 minutes 
### Validate the alerts 
- [ ] Confirm Event ID 5159 or sysmon event ID 3 indicating inbound traffic to port 3389 (RDP)
- [ ] Confirm multiple event ID 4625 (logon type 3) indicating failed login
- [ ] Confirm event ID 4624 (long type 3 or 10) 
- [ ] Check: Is the IP address engaged in the action is from an internal network (if local IP-> false positive)
- [ ] check: Is the account recorded in the successful login was in the list of previous failed authentication attempts

### Quick Context Gathering
```QKL 
SecurityEvent
| where  EventID in (5159, 3, 4625, 4624)
| where TimeGenerated > ago(1d)
| where IpAddress == "<Ip_address>"
| project TimeGenerated, EventID, Computer TargetUserName, SubjectUserName, SubjectDomainName, logonType
| ordered by TimeGenerated desc
```

### Decision Point
- [ ] Escalate if: remote IP + large record of failed attempt
- [ ] close if: local IP + legitimate user accounts 

## Investigation 15 minutes
### Evidence collection 
- [ ] Collect logs relates to events 4625, 3, 5156, 4624 for the specific host
- [ ] Check authentication timeline 
- [ ] Determine if brute force succeeded 
- [ ] If successful check for post-compromise activity

### Command to Run 

**Check if brute force succeed**
```KQL 
securityEvent
| where IpAddress == "<Source_IP>"
| where EventID in (4624, 4625)
| where logonType in (10, 3)
| where TimeGenerated > ago(1d)
| summarize 
    FailedAttempts = countif(EventID == 4625)
    successfulLogon = countif(EventID == 464)
    Accounts = make_set(TargetUserName)
    by  computer, IpAddress
| extend CompromiseConfirmed = if (successfulLogon > 0, "Yes - CRITICAL", "NO - ATTEMPTS ONLY")
```
**If successful logon found check for RDP session** 
``` KQL
SecurityEvent
| where EventID == 4624 and logonType == 10
| where IpAddress == "<Source_IP>"
| where TimeGenerated > ago(1d)
| Where Computer == "<Affected_Computer>"
| project TimeGenerated, Computer, TargetUserName, IpAddress, logonType
``` 

**Check for post compromise activity (if RDP session is established)**
```KQL 
SecurityEvent
| where EventID in (4688, 4698, 7045, 5140)
| where TimeGenerated > datetime(RDP_Session_Start)
| where computer == "<Compromise_Computer>"
| project TimeGenerated, EventID, Account, ProcessName, ServiceName, ShareName
```


### Key Question to Answer
- [ ] Are all the failed attempt contain valid domain users or random string
- [ ] Was an interactive RDP session established ?
- [ ] Did the brute force succeeded
- [ ] Is the user of the valid authentication in the administrative group
- [ ] If compromise what action did the attacker take after 

### Decision Point 
**Proceed to Path A or B based on the Investigation**

## Path A: Brute force failed 
### Containment 15 minutes
**No user account compromise - focus on network blocking** 

- [ ] Block source IP at firewall level 
- [ ] Monitor for additional attempt from the same IpAddress
- [ ] No account suspension needed (no compromise)

**Coordinate with Network Team:**
- [ ] Block IP <Source_IP> at perimeter firewall
- [ ] Check for other IPs from same /24 subnet attempting brute force
- [ ] Consider temporary geo-blocking if foreign attack source

### Eradication (Not applicable)
**No compromise occurred - nothing to eradicate**

### Recovery 5 minutes
- [ ] verify RDP still accessible from legitimate admin portal 
- [ ] Confirm firewall block is working
- [ ] Monitor for 24 hours for additional attempts

### Post-Incident
**Document attempts and harden defenses**
- [ ] Update Threat intel with attacker IP/subnet
- [ ] Considering implementing RDP Network Level authentication (NLA)
- [ ] Consider RDP access only trough VPN
- [ ] Review account lookup policy 

## Path B - Brute Force Successful + RDP Session Established


###  containment 30 minutes 
### Immediate Actions
- [ ] terminate active RDP session 
```powershell
Invoke-Command - ComputerName "<Compromise_Computer>" -ScriptBlock{
query session
logoff /server
}
```
- [ ] Disable the compromise account
```powershell
Disable-ADAccount -Identity "<account_name>"
```
- [ ] Reset the password of the affected account
```powershell
Set-ADAccountPassword -Identity "<affected_user>" 
-Reset -NewPassword (ConvertTo-SecureString "TempP@ss123!$(Get-Random)" -AsPlainText -Force)
Set-ADUser -Identity "<affected_user>" -ChangePasswordAtLogon $true 
```  
**Coordinate with Network Team**
- [ ] Block the IP at the perimeter firewall 
- [ ] Bock outbound traffic through the 3389 port to external IP
- [ ] Request VLAN isolation if lateral movement detected
 
### Eradication
**check for persistence mechanisms create during RDP session** 
```powershell
# Check for scheduled tasks created during session
Get-ScheduledTask -CimSession "" | 
    Where-Object {$_.Author -like "**" -or 
                  $_.Date -gt (Get-Date).AddHours(-24)}

# Check for new services
Get-Service -ComputerName "" | 
    Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -eq 'Running'}

# Check registry run keys
Invoke-Command -ComputerName "" -ScriptBlock {
    Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
}

Get-ADUser -Filter {whenCreated -gt (Get-Date).AddHours(-24)}
``` 
**If malicious artifacts founds**
- [ ] Remove malicious scheduled tasks
- [ ] Delete unauthorized services
- [ ] Remove registry persistence
- [ ] Delete any dropped files 

### Recovery 30 minutes
- [ ] scan host with EDR/AV for malware 
```powershell
Invoke-Command -ComputerName "<Compromise_Computer>" -ScriptBlock{
    Start-MpScan -ScanType FullScan 
}
```

- [ ] Verify no additional persistence exists
- [ ] Re-enable user account only after verification
- [ ] Monitor account for 72 hours
- [ ] Un-isolate host after full validation

## Post-Incident (Both Path)
### Documentation 
- [ ] Document incident timeline and action taken
- [ ] Register the TTPs of the attacker
- [ ] Record wether the brute force succeed or not 
- [ ] if successful: Document post incident activity 

### IOC To track 

| Type | Value | Context |
|------|-------|---------|
| Ip address | <Ip_address> | Brute force source |
| User Account | <Compromise_user> | compromise account (path B) | 
| Host Name | <Compromise_Computer> | compromise computer (path B) |
| Session Start | <Time_stamp> | time stamp of the establishment of the rdp session|
| Artifacts Created | <Task/File/Process> | persistence mechanisms (path B) |

### Lessons Learned
**Attack Success Analysis**
- [ ] Why was the RDP exposed to the internet?
- [ ] Was account lockout bypass? how?
- [ ] Did the attacker succeeded in establishing an RDP session?
- [ ] if yes: what was done during the session 

**Detection Effectiveness**
- [ ] how long between first attempt and discovery?
- [ ] Did correlation rule accurately identified the brute force?
- [ ] Was post-compromise activity detected 

**Defense Gap Identified**
- [ ] Is RDP accessible through the internet?
- [ ] Is NLA is enabled?
- [ ] Are account lookup thresholds appropriate?
- [ ] Should the RDP be trough VPN only?

**Recommendations:**
- [ ] Implement RDP access via VPN/bastion host only
- [ ] Enable Network Level Authentication (NLA)
- [ ] Implement MFA for RDP access
- [ ] Review and strengthen account lockout policy
- [ ] Consider geo-blocking for RDP if appropriate

### Escalation Criteria
**Escalate to Tier 2/IR if:**
- [ ] RDP session was established (Path B)
- [ ] Evidence of lateral movement from compromised host
- [ ] Persistence mechanisms detected
- [ ] Data exfiltration suspected
- [ ] Multiple accounts compromised
- [ ] Attacker maintains access after remediation

