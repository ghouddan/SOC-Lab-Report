# Report 1 v.2

## Summary 
A domain user account experienced multiple failed login attempts followed by a successful authentication from the same source. The same credentials were used to access a different machine, indicating lateral movement within the environment. 

## Timeline of the events 
-  11:20 DC: Multiple failed attempts to the user “User1” account from the IP 192.168.57.1.
 - 11:25 DC: A successful authentication to the the account User1.
 - 11:30 WIN10: Successful authentication for user1 on WIN10 from 192.168.57.1 
 - 11:32 WIN10: The creation of a new service indicating remote execution with the account SYSTEM. 

## Evidence observed
DC machine : multiple events ID of 4625 and 4624 for user1
WIN10 machine: Security  Event id 4624 for user1 
WIN10 machine: System Event id 7045
Correlation:  performed using `@timestamp`, `winlog.event_data.IpAddress`, `event.code`, `host.name`

## Analyst Assessment 
The sequence of failed authentication attempts followed by a successful one across multiple machines strongly indicates a credential compromise and active lateral movement rather than user error.

## Recommended Action 
- Account blocking or suspension 
- Review the activity of the user on the machines that were affected 
- Increase surveillance on this kind of action 
- Recommend isolating affected hosts from the network pending investigation.
