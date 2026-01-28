## Attack: Request service tickets and crack them offline to get service account passwords.

### How it Works:

- Any domain user can request service tickets (TGS)
- Service tickets encrypted with service account's password hash
- Attacker requests tickets for accounts with SPNs
- Takes encrypted tickets offline  and cracks them
- Weak passwords = crackable hashes

### Tool: Impacket GetUserSPNs
``` bash
impacket-GetUserSPNs corp.local/user1:Password123! -dc-ip 192.168.57.100 -request
```
**Goal**: Obtain service account credentials (often have high privileges)    
