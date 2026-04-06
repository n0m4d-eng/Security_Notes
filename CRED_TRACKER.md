# CRED_TRACKER — Credential Log

Copy a new block for every credential found. Fill in every field. Mark services as ✓ (worked), ✗ (failed), or — (not tested).

---

## Credential Block Template

```
## Cred #[N]

| Field        | Value |
|--------------|-------|
| Username     |       |
| Password     |       |
| Hash         |       |
| Hash type    |       |
| Source       |       |
| Found at     |       |

### Tried against

| Service | Port | Result | Notes |
|---------|------|--------|-------|
| SSH     | 22   |  —     |       |
| SMB     | 445  |  —     |       |
| RDP     | 3389 |  —     |       |
| WinRM   | 5985 |  —     |       |
| FTP     | 21   |  —     |       |
| MSSQL   | 1433 |  —     |       |
| MySQL   | 3306 |  —     |       |
| HTTP    | 80   |  —     |       |
| HTTPS   | 443  |  —     |       |
| LDAP    | 389  |  —     |       |
```

---

## Active Credentials

<!-- Paste filled-in blocks below this line -->

---

## Hash Cracking Queue

| Hash | Type | Tool | Status | Plaintext |
|------|------|------|--------|-----------|
|      |      |      | pending|           |

**Quick crack commands:**

```bash
# NTLM (mode 1000)
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt --force

# NetNTLMv2 (mode 5600) — from Responder
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt --force

# Kerberoast TGS-REP (mode 13100)
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt --force

# AS-REP (mode 18200)
hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt --force

# Linux SHA-512 /etc/shadow (mode 1800)
hashcat -m 1800 hashes.txt /usr/share/wordlists/rockyou.txt --force

# John — auto-detect
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --show hashes.txt
```

See [cheatsheets/credential_cracking.md](cheatsheets/credential_cracking.md) for full hash mode table.

---

## Flags Captured

| Machine | Flag file | Contents | Captured at |
|---------|-----------|----------|-------------|
|         | local.txt |          |             |
|         | proof.txt |          |             |

---

## → Where to go next
- Have hashes to crack → [cheatsheets/credential_cracking.md](cheatsheets/credential_cracking.md)
- Have plaintext creds → test against all services (fill in table above)
- Have domain creds → [active_directory/active_directory_enumeration.md](active_directory/active_directory_enumeration.md)
- Nothing cracking → [STUCK.md](STUCK.md)
