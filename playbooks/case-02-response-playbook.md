# Scheduled Task Creation Via Remote Connection (persistence technique)

**Alert triggered:** scheduled task creation via remote connection    
**MITRE ATT&CK:** T1053.005      
**Severity:** High    
**MTTR:** 15 minutes triage, 1 hour 30 minutes full containment 

## Initial Triage 15 minutes

### Validate the Alert 
- [ ] Confirm event Id 4624 (logon type 3), Event ID 5145 (admin share access) and Event ID 4698 (scheduled task creation) are present in the logs
- [ ] confirm the time correlation between the admin share access and the scheduled task creation
- [ ] check : Is the account used in the action is a non-administrative account (if administrative -> false Positive)
- [ ] check ; Is the source IP address of the action is from an internal network (if local IP -> false Positive)

### Quick Context Gathering 
``` KQL 
SecurityEvent
| where EventID in (4624, 5145, 4698)
| where TimeGenerated > ago(1d)
| where TargetUserName == "<TargetUserName>" or SubjectUserName == "<SubjectUserName>"
| project TimeGenerated, EventID, Computer, TargetUserName, SubjectUserName, SubjectDomainName, IpAddress, ShareName, TaskName
| order by TimeGenerated desc 
``` 

### Decision Point
- [ ] Escalate if : Non admin user + Remote IP + suspicious scheduled task name or path + time correlation confirmed
- [ ] Close if : Admin user + local IP + known scheduled task name or path 

## Investigation 15 minutes

### Evidence collection 
- [ ] Collect logs related to Event ID 4624, 5145 and 4698 for the specific user and host
- [ ] collect information about the scheduled task created (name, path, action, triggers)
- [ ] Analyze scheduled task execution history if available 
- [ ] Check for any related process creation events that may indicate execution of the scheduled task 


### Command to Run 

```KQL 
securityEvent
| where EventID in (4624, 5145, 4698, 4688)
| where TimeGenerated > ago(1d) 
| where TargetUserName == "<TargetUserName>" or SubjectUserName == "<SubjectUserName>"
| project TimeGenerated, EventID, Computer, TargetUserName, SubjectUserName, SubjectDomainName, IpAddress, ShareName, TaskName, NewProcessName
| order by TimeGenerated desc 
```

```powhershell
Get-ScheduledTask -ComputerName "<ComputerName>" -TaskName "<TaskName>" | Format-List *
Get-ScheduledTask -ComputerName "<ComputerName>" | Where-Object {$_.TaskPath -notlike '\Microsoft*'}
Get-ScheduledTaskInfo -ComputerName "<ComputerName>" -TaskName "<TaskName>" | Format-List *
``` 
### Key Questions To Answer
- [ ] Was the scheduled task executed after creation 
- [ ] Does the affected user have a history of similar actions 
- [ ] Was the activity from an internal of external IP address 
- [ ] is there any indication of a process spawning after the scheduled task creation
- [ ] Is there any indication of lateral movement activity from the affected host
- [ ] Is there any indication of data exfiltration activity from the affected host  

## Containment 30 minutes

### Immediate Actions 
- [ ] Disable the created scheduled task 
- [ ] Suspend the affected user account 
- [ ] Block any process related to the scheduled task action 
- [ ] Isolate the affected host from the network if evidence of lateral movement or data exfiltration is found 
- [ ] Force a password reset on the affected user account
- [ ] Block the IP address if it's external or suspicious
- [ ] Monitor the affected host and user for any further suspicious activity

### Commands to Run 

```Powershell 
# Disable the scheduled task from the affected host
Invoke-Command -ComputerName "<ComputerName>" -ScriptBlock {Disable-ScheduledTask -TaskName "<TaskName>" -TaskPath "<TaskPath>"}
```

```Powershell
# Suspend the affected user account
Disable-ADAccount -Identity "<affected_user>"
```

```Powershell
# Force password rest for the affected user
Set-ADAccountPassword -Identity "<affected_user>" 
-Reset -NewPassword (ConvertTo-SecureString "TempP@ss123!$(Get-Random)" -AsPlainText -Force)
Set-ADUser -Identity "<affected_user>" -ChangePasswordAtLogon $true 
```

### Coordinate with Network Team 
- [ ] Block the IP at the perimeter firewall 
- [ ] Request VLAN isolation if lateral movement detected

### Evidence Preservation
- [ ] document the created scheduled task before deletion 
- [ ] Export relevant logs for further analysis
- [ ] Take a forensic image of the affected host if necessary 

### Commands to Run 
```powershell
# Save scheduled task details
Get-ScheduledTask -ComputerName "<ComputerName>" -TaskName "<TaskName>" 
| Export-ScheduledTask 
| Out-File -FilePath "C:\IR\ScheduledTask_<TaskName>_details.xml"
```

```powershell
# Create a forensic image of the affected host
wbadmin start backup -backupTarget:C:\IR\ -include:C: -allCritical -quiet
```

## Eradication 15 minutes

### Removal Actions
- [ ] Delete the created scheduled task permanently
- [ ] Scan the affected host for any other artifacts of compromise
- [ ] Remove any related malicious files or processes
- [ ] Ensure no other persistence mechanisms are present on the host

### Commands to Run 

```Powershell
# Delete the scheduled task from the affected host
Invoke-Command -ComputerName "<ComputerName>" 
-ScriptBlock {Unregister-ScheduledTask -TaskName "<TaskName>" -TaskPath "<TaskPath>" -confirm:$false}
```

```Powershell
# Scan the affected host for malicious files
Invoke-Command -ComputerName "<ComputerName>" -ScriptBlock {Start-MpScan -ScanType FullScan}
```
```KQL 
// Systems accessed by this IP/user in last 24h
SecurityEvent
| where IpAddress == "<IpAddress>" or TargetUserName == "<TargetUserName>"
| where EventID == 4624
| where TimeGenerated > ago(24h)
| summarize SystemsAccessed=dcount(Computer), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by IpAddress, TargetUserName
| where SystemsAccessed > 1
```

## Recovery 15 minutes
### Restoration steps 
- [ ] Re-enable the affected user account after verification 
- [ ] Monitor the affected host and user for 72 hours post-incident
- [ ] Rejoin the host to the network if isolated
- [ ] Ensure all systems are patched and up to date

## Post-Incident
### Documentation
- [ ] Document the incident details, actions taken, and lessons learned
- [ ] Record the TTPs used and update detection rules accordingly
- [ ] Document any gaps in detection and mitigation strategies

### Lessons Learned 
- [ ] Why did this attack succeed (credential weakness, missing control, configuration gap)
- [ ] How long between attack start and detection 
- [ ] What telemetry was missing that would have helped 
- [ ] What security control could have prevented this 
- [ ] What defense improvement are needed 

### IOC to Track 

| Type | Value | context |
|------|-------|---------|
| User Account | <Target_user_name> | Affected user account  | 
|  Hostname | <Computer_name> | Affected host  | 
|  IP Address | <Ip_address> | Source IP of the remote connection  | 
|  Scheduled Task Name | <Task_name> | Name of the created scheduled task  | 
|  Scheduled Task Path | <Task_path> | Path of the created scheduled task  | 
|  Process Name | <New_processname> | Process spawned by the scheduled task  | 

### Escalation Criteria
**Escalate to Tier 2 if:**     
- [ ] Evidence of lateral movement to other systems
- [ ] Presence of malware or backdoor on the affected host 
- [ ] Detection of malicious action after re-enabling the user account
- [ ] Inability to determine the full scope of the incident

