# Remote Command Execution Via Service Creation - Response Playbook

**Alert Triggered:** [Remote Command Execution via Service Creation]    
**MITRE ATT&CK:** T1543.003, T1021    
**Severity:** Hight    
**MTTR Target:** 2 hours full containment    

## Initial Triage 15 minutes

### Validate the Alert
- [ ] Confirm Event ID 4624 (Network Logon) and Event ID 7045 (Service Creation Under SYSTEM context) are present in the logs.
- [ ] check: Is the account used for the access is a non-administrative user (if administrative -> false positive).
- [ ] check: source IP address in the management subnet or known admin IP (if yes -> false positive).
- [ ] check: time correlation between the network logon and service creation.

### Quick Context Gathering 
``` KQL
SecurityEvent
| where EventID in (4624, 7045, 4688)
| where TimeGenerated > ago(1h)
| where TargetUserName == "<Alert_User>"
| project TimeGenerated, EventID, Computer, TargetUserName, IpAddress, ServiceName, ProcessName, ParentProcessName
| order by TimeGenerated desc
``` 
### Decision Point
- [ ] Escalate if : Non-admin user + Unknown source IP + suspicious service name 
- [ ] Close if : User is admin + activity during maintenance window + known source IP

## Investigation 30 minutes

### Evidence collection 
- [ ] Collect service information and details
- [ ] Check authentication window
- [ ] check for lateral movement from the same source IP
- [ ] Analyze process execution if present (Event 4688)  

### Command and Queries to Run
```Powersell
Get-Service -ComputerName <Target_Computer> -Name <Service_Name> | Format-List *
Get-WinEvent -ComputerName <Target_Computer> -FilterHashtable @{LogName='Security'; ID=4624,4625} | Where-Object {$_.Properties[5].Value -eq "<Target_User>"}
```

```kql
// Systems accessed by this user from same source IP
SecurityEvent
| where IpAddress == "<Source_IP>"
| where TargetUserName == "<Alert_User>"
| where EventID == 4624
| where TimeGenerated > ago(24h)
| summarize SystemsAccessed=dcount(Computer), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by Computer
| where SystemsAccessed > 1
```


### Key Question to Answer
- [ ] Was the activity from an internal source IP or external
- [ ] Is the service known or suspicious 
- [ ] Does the user have a history of similar activities 
- [ ] Is there evidence of lateral movement 

## Containment  15 minutes
### Immediate Actions
- [ ] Disable the created service 
- [ ] Block any action coming from the same source IP
- [ ] Reset the compromised user credentials
- [ ] Isolate the affect hots from the network if lateral movement detected

### Commands to Run 

```Powershell 
Stop-Service -Name <Service_Name> -ComputerName <Target_Computer> -Force
Disable-ADAccount -Identity "<Compromised_User>"
``` 

```Powershell
Set-ADAccountPassword -Identity "<User_Name>" -Reset -NewPassword (ConvertTo-SecureString 'Newpassword' -AsPlainText -Force)
Set-ADUser -Identity "<User_Name>" -changePasswordAtLogon $true
```

**Optional - Windows Firewall Block (if needed):**
```powershell
New-NetFirewallRule -DisplayName "Block Attacker" -Direction Inbound -RemoteAddress <Source_IP> -Action Block
```

**Coordinate with Network Team:**
- [ ] Block source IP at perimeter firewall: <Source_IP>
- [ ] Request VLAN isolation if lateral movement detected

### Evidence Preservation

**Before deleting service, document it:**
```powershell
# Capture service details
Get-WmiObject Win32_Service -ComputerName  | 
    Where-Object {$_.Name -eq ""} | 
    Select-Object Name, DisplayName, PathName, StartMode, State, StartName | 
    Export-Csv -Path "C:\IR\service__details.csv" -NoTypeInformation

# Hash the service binary
Get-FileHash -Path "\\\C$\" -Algorithm SHA256
```

## Eradication 
### Removal Actions
- [ ] Delete the created service permanently
- [ ] Scan network for any other suspicious service or processes
- [ ] Check for persistence mechanisms 
- [ ] check for malware or backdoor 

### Commands to Run 
```Powershell
sc.exe \\<Target_Computer> delete "<Service_Name>"
```

```Powershell
Get-Process -ComputerName <Target_Computer> | Where-Object {$_.ProcessName -like "*suspicious_pattern*"} | Stop-Process -Force
```

```KQL 
SecurityEvent
| where IpAddress == "<Source_IP>" or TargetUserName == "<Target_User>"
| where TimeGenerated > ago(7d)
| where EventID in (4624, 4625, 7045, 4688, 5140)
| project TimeGenerated, EventID, Computer, IpAddress, TargetUserName, ServiceName
| sort by TimeGenerated desc
```

## Recovery 
### Restoration Steps
- [ ] Re-enable user account only after verification
- [ ] Scan host with EDR/AV and confirm clean
- [ ] Monitor account activity for 72 hours post-incident
- [ ] Review and update software and security policies 

## Post-Incident 

### Documentation
- [ ] Document the incident timeline and action taken 
- [ ] Record the attacker TTP 
- [ ] document the lessons learned 

### IOCs to track 

| Type | Value | Context |
|------|-------|---------|
| IP Address | <IP_Address> | Source of the attack |
| Service Name | <Service_Name> | Created service during the attack |
| User Account | <Target_User> | Compromised user account used to take on the actions |
| Process created | <Process_Name> | suspicious process executed |
| Parent Process | <Parent_Process_Name> | Parent process of the suspicious executed process | 

### Escalation Criteria
**Escalate to Tier 2 if:**
- [ ] Evidence of lateral movement to other systems 
- [ ] detected of a persistence mechanisms 
- [ ] Present of malware or backdoor 
- [ ] Inability to contain or eradicate the threat within the MTTR target time

