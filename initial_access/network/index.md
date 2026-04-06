# Network Initial Access — Triage

### What brings you here
You found a non-web network service and need to know which attack track to follow.

---

## Checklist — Do These First

```bash
# Run targeted scripts against any open service
nmap -sC -sV -p <port> <IP>

# Banner grab anything unknown
nc -nv <IP> <port>
```

---

## Service Routing Table

| Port | Service | First step | Go to |
|------|---------|-----------|-------|
| 21 | FTP | Test anonymous login | [ftp_exploitation.md](ftp_exploitation.md) |
| 139, 445 | SMB | Test null session | [smb_exploitation.md](smb_exploitation.md) |
| 161 UDP | SNMP | Brute community strings | [snmp_disclosure.md](snmp_disclosure.md) |
| 111, 2049 | NFS | List exports | [nfs_exploitation.md](nfs_exploitation.md) |
| 1433 | MSSQL | Test `sa` with empty password | [database_rce.md](database_rce.md) |
| 3306 | MySQL | Test root with no password | [database_rce.md](database_rce.md) |
| 5432 | PostgreSQL | Test postgres with no password | [database_rce.md](database_rce.md) |
| Any | Outdated version | searchsploit / MSF | [service_exploitation.md](service_exploitation.md) |

---

## What Did You Find?

| Finding | Next action |
|---------|-------------|
| FTP anonymous login works | [ftp_exploitation.md](ftp_exploitation.md) |
| SMB null session gives shares | [smb_exploitation.md](smb_exploitation.md) |
| SNMP `public` string responds | [snmp_disclosure.md](snmp_disclosure.md) |
| NFS export listed | [nfs_exploitation.md](nfs_exploitation.md) |
| DB service accepts connection | [database_rce.md](database_rce.md) |
| Service version is old | [service_exploitation.md](service_exploitation.md) |
| Credentials found in a file/share | [../../CRED_TRACKER.md](../../CRED_TRACKER.md) → test everywhere |

---

## Dead Ends
- All services require auth and no creds found → go to web port or check SNMP/NFS/UDP
- Nothing exploitable → [../../STUCK.md](../../STUCK.md)

---

## → Where to go next
- Got a shell → [../../post_exploitation/index.md](../../post_exploitation/index.md)
- Found creds → [../../CRED_TRACKER.md](../../CRED_TRACKER.md)
- Nothing worked → [../../STUCK.md](../../STUCK.md)
