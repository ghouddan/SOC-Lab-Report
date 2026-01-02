# Remote Command Execution Via Service Creation - Detection Gaps Analyst 

## Chain of attack
Multiple authentication failures to a domain user account were followed by a successful network logon from the same source. The compromised credential where used to access a secondary domain host, where remote code execution was achieved via service creation under SYSTEM context.

## Detection goal
Detect remote command execution on a Windows host using valid credentials.

## Detection Signal 

Signal 1: Network logon by a non-administrative account
Event Id 4624 with logon type 3, indicating a network-based authentication, when observed against a standard domain user, this may indicate credential use for remote access rather than an interactive login.

Signal 2: Service Creation Under SYSTEM Context
Event 7045 indicates the installation of a windows service. Services are usually created during software installation or administrative maintenance. Service creation under the SYSTEM context directly after a network login might strongly suggest remote code execution 

Signal 3: Temporal correlation 
The same source IP performed multiple authentications across the domain host using the same credentials. A service creation 5 minutes after a successful network logon, establishing a strong temporal correlation between authentication and execution 

## Detection Gaps Identified
Event id 7045 do not include the IP, limiting attribution of remote execution activity 
Absence of the event code 4688 prevents visibility into process creation and the parent process 
Lack of command-line and parent process restricts the identification of the execution method.

## False Positive Considerations

 Legitimate administrative activities such as software deployment, patching, or remote management tools may generate similar service creation events. Validation should include verification of authorized maintenance windows, known administrative hosts, and approved service installation activity