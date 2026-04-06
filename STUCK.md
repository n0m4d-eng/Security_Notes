# STUCK — Reset Checklist

### What brings you here
You have been on a machine for more than 45 minutes without meaningful progress.

Stop what you are doing. Run through every item below before trying any new exploit.

---

## The Checklist

### 1. Port Coverage — Have you scanned everything?

```bash
# Full TCP port range (not just top 1000)
nmap -p- --min-rate 5000 -T4 <IP> -oN full_tcp.txt

# UDP — the most commonly missed scan
sudo nmap -sU --top-ports 100 <IP> -oN udp_scan.txt

# Service versions on every open port
nmap -sC -sV -p <all_open_ports_csv> <IP> -oN versions.txt
```

| Missed scan | What it finds |
|-------------|---------------|
| UDP | SNMP (161), TFTP (69), IPMI (623), DNS (53), NTP (123) |
| Ports 1024–65535 | Non-standard HTTP, obscure services, dev servers |
| `-sC` scripts | Default creds, anonymous access, version disclosure |

---

### 2. Virtual Hosts — Is there a vhost you have not tried?

```bash
# DNS enumeration for vhosts
dig any <domain> @<IP>
gobuster vhost -u http://<IP> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

# Check SSL certificate for Subject Alternative Names
openssl s_client -connect <IP>:443 </dev/null 2>/dev/null | openssl x509 -noout -text | grep -A2 "Subject Alternative"

# Check /etc/hosts on target if you already have a shell
cat /etc/hosts
```

---

### 3. SSL Certificates — Did you read the cert?

```bash
openssl s_client -connect <IP>:443 </dev/null 2>/dev/null | openssl x509 -noout -text
```

Look for:
- Hostnames in CN / SAN fields → add to `/etc/hosts`, test as vhost
- Organisation name → hints at internal naming conventions
- Email addresses → valid usernames

---

### 4. Credential Reuse — Have you tried every credential everywhere?

Go to [CRED_TRACKER.md](CRED_TRACKER.md) and verify every credential has been tested against every relevant service.

Common misses:
- SSH with a web app password
- SMB with a database password
- RDP with any local account credential
- The username as the password
- `admin:admin`, `admin:password`, `root:root`

```bash
# Spray a single password across SMB
crackmapexec smb <IP> -u users.txt -p '<password>'

# Test SSH with a list of credentials
hydra -L users.txt -P passwords.txt ssh://<IP>
```

---

### 5. Directory Busting — Have you gone deep enough?

```bash
# Did you bust directories on every web port, not just 80/443?
# Did you try extensions?
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -u http://<IP>/FUZZ -e .php,.txt,.bak,.old,.conf,.zip -o ffuf_deep.txt

# Did you bust subdirectories of found directories?
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
     -u http://<IP>/api/FUZZ

# Did you try a bigger wordlist?
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt \
     -u http://<IP>/FUZZ
```

---

### 6. Source Code & Metadata

```bash
# Check page source for comments, hidden fields, API endpoints
curl -s http://<IP>/ | grep -E "<!--.*-->|/api/|token|secret|key|pass|user"

# Check robots.txt and sitemap
curl http://<IP>/robots.txt
curl http://<IP>/sitemap.xml

# Check .git exposure
curl http://<IP>/.git/HEAD
git-dumper http://<IP>/.git ./git_dump   # if exposed
```

---

### 7. Service Version Exploits — Did you check searchsploit?

```bash
# For every service version found
searchsploit "<service> <version>"
searchsploit "<service>" | grep -i "rce\|exec\|overflow\|unauth"

# Cross-reference with exploit-db and GitHub
```

---

### 8. Protocol-Specific Misses

| Service | Commonly missed check |
|---------|-----------------------|
| SMB | Null session: `crackmapexec smb <IP> -u '' -p ''` |
| FTP | Anonymous login: `ftp <IP>` → user: `anonymous` |
| SNMP | Community string brute: `onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <IP>` |
| NFS | Export check: `showmount -e <IP>` |
| LDAP | Anonymous bind: `ldapsearch -x -H ldap://<IP> -b "dc=domain,dc=com"` |
| SMTP | User enumeration: `smtp-user-enum -M VRFY -U users.txt -t <IP>` |
| MySQL/MSSQL | Root with no password: `mysql -u root -h <IP>` |

---

### 9. Internal Services — Are you looking at everything on the target?

If you already have a shell:

```bash
# What is listening internally that is not exposed externally?
netstat -tlnp
ss -tlnp

# Services listening on 127.0.0.1 need port forwarding to reach
# See: cheatsheets/pivoting_and_port_forwarding.md
```

---

### 10. When to Move On

Move on after confirming all of the above when:
- All ports (TCP full range + UDP top 100) scanned
- All web ports directory-busted with extensions
- All vhosts / SSL SANs tested
- All found credentials tried against all services
- All service versions checked in searchsploit

If still stuck after all that → this machine may require chaining findings or looping back after more access elsewhere. Document what you have and move to the next target.

---

## → Where to go next
- Found a new service or port → [master_workflow.md](master_workflow.md)
- Found credentials → [CRED_TRACKER.md](CRED_TRACKER.md) then test for reuse
- Ready to try an exploit → [initial_access/network/service_exploitation.md](initial_access/network/service_exploitation.md)
