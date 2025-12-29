# Post-Authentication Lateral Movement via Windows Execution Primitives

## Detection Objective
Detect post-authentication lateral movement using Windows-native execution mechanisms  

## Attack Chain
A network-based authentication to a company domain, using a legitimate user account, was followed by a remote execution primitive invoked locally

## Detection Signal 

Signal 1: Network Logon
	Event ID 4624 with the type 3 logon indicates a network-based logon with a non-administrative account.

Signal 2: Network-based Administrative Share Access 
	Event ID 5145 indicates access to the Administrative share (ADMIN$, IPC$) from a remote source, when triggered by a standard user and not an administrative or management account. This suggests a remote interaction with the system.

Signal 3: Scheduled Task Creation by a non-Privileged account
	Event ID 4698 records the creation of a scheduled task on the host machine. When triggered by a domain user outside the expected administrative workflow, this may indicate a suspicious task-based persistence execution.

Signal 4: Service Creation Under System Account 
	Event ID 7045 indicates the installation of a Windows service. Services are usually created during software installation or administrative maintenance. Service creation directly after a network logon might strongly indicate remote code execution.

Correlation:
    Network authentication from a remote machine not belonging to an administrative or management group, followed in a short window of time by an act of post-exploitation executed by the same account of authentication from the same source  IP, establishes a strong temporal correlation between authentication and execution.

## Detection Gap 
Lack of authentication context:
 Event ID 4698 does not include the source IP address or logon type, which limits attribution to a specific remote authentication event.

Execution uncertainty:
Task creation does not confirm task execution; additional telemetry (e.g., task run events or process creation logs) is required to confirm impact.

Limited origin attribution:
Event ID 5145 confirms remote access but does not directly identify the command or tool responsible for task creation.

Incomplete events:
Absence of event code 4688 prevents visibility into the process creation and parent process.
Lack of command-line and  parent process restricts the identification of the execution method. 

## False Positive
- Legitimate administrative activity, such as software deployment, patching, or a system management tool, may create a scheduled task remotely.

- IT automation platforms or scripts may access administrative shares and register tasks as normal operations. 

- Management tools may generate similar service creation events. 

Validation should include verification of authorized maintenance windows, known administrative hosts, and approved service installation activity

