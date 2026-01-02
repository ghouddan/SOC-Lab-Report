# Scheduled Task Creation Via remote connection 

## Detection Objective  
	Detect remote scheduled task creation on a domain-joined Windows following a remote network interaction.

## Attack Chain
A domain user account accessed a domain-joined host via a network-based connection.
Shortly after, a scheduled task was created on the host, indicating potential persistence or post-authentication lateral movement activity.

## Detection Signal
Signal 1: Network-Based Administrative Share Access  
    Event ID 5145 indicates access to administrative share (ADMIN$, IPC$)from a remote source. When observed outside of the known management host, this suggests a remote interaction with the system. 	

Signal 2: Scheduled Task Creation By Non-Administrative Account
	Event ID 4698 records the creation of a scheduled task on the host machine. When triggered by a stander user and not an administrative or management account, this activity may indicate suspicious task-based persistence execution.

Signal 3: Temporal correlation 
	A scheduled task creation event occurring shortly after a remote network interaction strengthens confidence that the activity is attacker-driven rather than benign background behavior.

## Detection Gap 
Lack of authentication context:
 	Event ID 4698 does not include the source IP or logon type, limiting attribution to a specific remote authentication event.

Execution uncertainty:
	 Task creation does not confirm task execution; additional telemetry (e.g., task run events or process creation logs) is required to confirm impact.

Limited origin attribution:
	 Event ID 5145 confirms remote access but does not directly identify the command or tool responsible for task creation.

## False Positive 
Legitimate administrative activities, such as software deployment, patching, or system management tools, may create scheduled tasks remotely.
IT automation platforms or scripts may access administrative shares and register tasks as part of normal operations.
Validation should include confirmation of authorized maintenance windows, known management hosts, and approved scheduled tasks.




