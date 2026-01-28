## Attack: Execute commands remotely using Windows Management Instrumentation.

### How it Works:

- Authenticate with admin credentials
- Use WMI protocol to spawn processes
- Commands execute via wmiprvse.exe as parent process
- Less noisy than service creation

### Tool: CrackMapExec with wmiexec
```bash
crackmapexec smb 192.168.57.101 -u user1 -p Password123! -x "whoami" --exec-method wmiexec
```
**Goal**: Remote code execution, lateral movement alternative to SMB    
