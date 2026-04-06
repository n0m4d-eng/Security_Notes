# Master Workflow — Decision Engine

This is a routing document. It does not contain technique detail. It tells you what to do next based on what you find. Follow the links for the commands.

---

## Machine Status Tracker

Copy one block per machine at the start of every engagement.

```
## Machine: [IP / Hostname]
OS guess      : [ ]
Open ports    : [ ]
Services      : [ ]

Initial access: [ ] Method: _______________  User: _______________
PrivEsc       : [ ] Method: _______________  User: _______________
Proof         : [ ] local.txt: _______________  proof.txt: _______________

Creds found   :
  - user:pass  (source: _______) → CRED_TRACKER #___
  - hash       (type: _________)  → CRED_TRACKER #___

Pivot required: [ ] Y / N  Subnet: _______________
```

---

## Phase 0: Prepare

- [ ] VPN connected, interface up
- [ ] Note-taking open, new page for this machine
- [ ] Listener ready (`rlwrap nc -lvnp 443`)
- [ ] HTTP server ready (`python3 -m http.server 80` from `/opt/tools/`)

---

## Phase 1: Scan

Run these in order. Do not skip to exploitation until all three are done.

```bash
# 1. Quick scan — find open ports fast
rustscan -a <IP> --ulimit 5000 -- -sC -sV | tee rustscan.txt

# 2. Full TCP range — catches non-standard ports
nmap -p- --min-rate 5000 <IP> -oN full_tcp.txt

# 3. UDP top 100 — catches SNMP, TFTP, IPMI
sudo nmap -sU --top-ports 100 <IP> -oN udp.txt
```

> If rustscan is unavailable: `nmap -sC -sV -p- --min-rate 5000 <IP>`

---

## Phase 2: Port Routing Table

Find your open port(s) below and follow the link.

### Web Ports

| Port                 | Service | Go to                                                                            |
| -------------------- | ------- | -------------------------------------------------------------------------------- |
| 80, 8080, 8000, 8888 | HTTP    | [initial_access/web/index.md](initial_access/web/index.md)                       |
| 443, 8443            | HTTPS   | [initial_access/web/index.md](initial_access/web/index.md) — read SSL cert first |

### File & Remote Services

| Port      | Service | Go to                                                                                                                                             |
| --------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| 21        | FTP     | [protocols_services/ftp.md](protocols_services/ftp.md) → [initial_access/network/ftp_exploitation.md](initial_access/network/ftp_exploitation.md) |
| 22        | SSH     | [protocols_services/ssh.md](protocols_services/ssh.md)                                                                                            |
| 111, 2049 | NFS     | [protocols_services/nfs.md](protocols_services/nfs.md) → [initial_access/network/nfs_exploitation.md](initial_access/network/nfs_exploitation.md) |
| 873       | Rsync   | [protocols_services/linux_remote_management.md](protocols_services/linux_remote_management.md)                                                    |

### Windows / SMB

| Port       | Service | Go to                                                                                                                                             |
| ---------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| 139, 445   | SMB     | [protocols_services/smb.md](protocols_services/smb.md) → [initial_access/network/smb_exploitation.md](initial_access/network/smb_exploitation.md) |
| 3389       | RDP     | [protocols_services/windows_remote_management.md](protocols_services/windows_remote_management.md)                                                |
| 5985, 5986 | WinRM   | [protocols_services/windows_remote_management.md](protocols_services/windows_remote_management.md)                                                |

### Databases

| Port | Service    | Go to                                                                                                                                         |
| ---- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| 1433 | MSSQL      | [protocols_services/mssql.md](protocols_services/mssql.md) → [initial_access/network/database_rce.md](initial_access/network/database_rce.md) |
| 3306 | MySQL      | [protocols_services/mysql.md](protocols_services/mysql.md) → [initial_access/network/database_rce.md](initial_access/network/database_rce.md) |
| 5432 | PostgreSQL | [initial_access/network/database_rce.md](initial_access/network/database_rce.md)                                                              |
| 1521 | Oracle TNS | [protocols_services/oracle_tns.md](protocols_services/oracle_tns.md)                                                                          |

### Active Directory / Kerberos

| Port       | Service  | Go to                                                                                                                         |
| ---------- | -------- | ----------------------------------------------------------------------------------------------------------------------------- |
| 53         | DNS      | [protocols_services/dns.md](protocols_services/dns.md) — zone transfer, vhost enum                                            |
| 88         | Kerberos | [active_directory/active_directory_enumeration.md](active_directory/active_directory_enumeration.md)                          |
| 389, 636   | LDAP/S   | [active_directory/active_directory_enumeration.md](active_directory/active_directory_enumeration.md)                          |
| 3268, 3269 | GC LDAP  | You're looking at a DC → [active_directory/active_directory_enumeration.md](active_directory/active_directory_enumeration.md) |

### Information / Management

| Port               | Service   | Go to                                                                                                                                             |
| ------------------ | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| 25, 587            | SMTP      | [protocols_services/smtp.md](protocols_services/smtp.md) — user enum                                                                              |
| 110, 143, 993, 995 | IMAP/POP3 | [protocols_services/imap_pop3.md](protocols_services/imap_pop3.md)                                                                                |
| 161 (UDP)          | SNMP      | [protocols_services/snmp.md](protocols_services/snmp.md) → [initial_access/network/snmp_disclosure.md](initial_access/network/snmp_disclosure.md) |
| 623 (UDP)          | IPMI      | [protocols_services/ipmi.md](protocols_services/ipmi.md) — hash dump                                                                              |

### Unknown / Non-Standard Port

```bash
# Banner grab
nc -nv <IP> <port>
curl http://<IP>:<port>/

# Probe with nmap
nmap -sC -sV -p <port> <IP>
```

Then route based on what you find.

---

## Phase 3: Initial Access Decision

| What you found      | What to do                                                                                           |
| ------------------- | ---------------------------------------------------------------------------------------------------- |
| Web login page      | [initial_access/web/index.md](initial_access/web/index.md) → SQLi / default creds                    |
| File upload         | [initial_access/web/index.md](initial_access/web/index.md) → file upload                             |
| URL parameter       | [initial_access/web/index.md](initial_access/web/index.md) → LFI / SSTI                              |
| SMB null session    | [initial_access/network/smb_exploitation.md](initial_access/network/smb_exploitation.md)             |
| FTP anonymous       | [initial_access/network/ftp_exploitation.md](initial_access/network/ftp_exploitation.md)             |
| SNMP public string  | [initial_access/network/snmp_disclosure.md](initial_access/network/snmp_disclosure.md)               |
| NFS no_root_squash  | [initial_access/network/nfs_exploitation.md](initial_access/network/nfs_exploitation.md)             |
| DB with weak creds  | [initial_access/network/database_rce.md](initial_access/network/database_rce.md)                     |
| Old service version | [initial_access/network/service_exploitation.md](initial_access/network/service_exploitation.md)     |
| Valid credentials   | Try SSH / SMB / RDP / WinRM — see [CRED_TRACKER.md](CRED_TRACKER.md)                                 |
| AD environment      | [active_directory/active_directory_enumeration.md](active_directory/active_directory_enumeration.md) |

---

## Phase 4: Post-Exploitation

Got a shell? → [post_exploitation/index.md](post_exploitation/index.md)

| Situation         | Go to                                                                                      |
| ----------------- | ------------------------------------------------------------------------------------------ |
| Linux shell       | [post_exploitation/index.md](post_exploitation/index.md) → Linux track                     |
| Windows shell     | [post_exploitation/index.md](post_exploitation/index.md) → Windows track                   |
| Found credentials | [CRED_TRACKER.md](CRED_TRACKER.md) → test for reuse / lateral movement                     |
| Need to pivot     | [cheatsheets/pivoting_and_port_forwarding.md](cheatsheets/pivoting_and_port_forwarding.md) |

---

## Phase 5: Report Flags

Before finishing any machine:

```bash
# Linux
cat /root/proof.txt
cat /home/*/local.txt

# Windows (cmd)
type C:\Users\Administrator\Desktop\proof.txt
type C:\Users\*\Desktop\local.txt
```

Screenshot: `whoami && hostname && cat proof.txt` (or `type` on Windows) in one shot.

---

## Stuck?

→ [STUCK.md](STUCK.md) — run the full reset checklist before trying anything new.
