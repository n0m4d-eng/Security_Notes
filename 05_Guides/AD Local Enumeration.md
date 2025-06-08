---
date: 2025-06-08
tags:
  - ActiveDirectory
  - Guide
  - Cheatsheet
---


```table-of-contents
```



# Flowchart
```mermaid
flowchart TD
    A([Start AD Pentest]) --> B[Network Enumeration]
    B --> B1["Discover Domain Controllers<br>(nslookup, BloodHound)"]
    B --> B2["Identify Users & Groups<br>(ldapsearch, PowerView)"]
    B --> B3["Map Network Shares<br>(net view, smbclient)"]
    B --> B4["Scan Open Ports/Services<br>(nmap, CrackMapExec)"]
    B --> B5["Check for Null Session<br>(rpcclient, enum4linux)"]
    
    B --> C[Initial Access Phase]
    C --> C1["Phishing Campaign<br>(Set payload delivery)"]
    C --> C2["Exploit Public Services<br>(OWA, RDP, VPN vulns)"]
    C --> C3["Password Attacks<br>(Spraying, Cred Stuffing)"]
    C --> C4["Abuse Exposed Creds<br>(Git leaks, Pastebin dumps)"]
    
    C --> D{Initial Compromise?}
    D -->|Yes| E[Establish Foothold]
    D -->|No| B
    
    E --> E1["Low-Priv Shell Access<br>(Metasploit, Covenant)"]
    E --> E2["Credential Harvesting<br>(Mimikatz, LaZagne)"]
    E --> E3["Establish Persistence<br>(Scheduled Tasks, Services)"]
    
    E --> F[Local Enumeration]
    F --> F1["User Context Checks<br>(whoami /priv, net user)"]
    F --> F2["OS/Software Audit<br>(systeminfo, chkrootkit)"]
    F --> F3["Network Config<br>(ipconfig, arp -a)"]
    F --> F4["Sensitive File Hunt<br>(Unattend.xml, backups)"]
    
    F --> G{Privilege Escalation?}
    G -->|Yes| H[Escalate Privileges]
    G -->|No| I[Lateral Movement]
    
    H --> H1["Kernel Exploits<br>(BeRoot, Watson)"]
    H --> H2["Token Manipulation<br>(Incognito, RottenPotato)"]
    H --> H3["Abuse Misconfigurations<br>(AlwaysInstallElevated)"]
    H --> I
    
    I --> I1["Pass-the-Hash<br>(Mimikatz, smbexec)"]
    I --> I2["Remote Exploitation<br>(PsExec, WMI)"]
    I --> I3["Delegation Abuse<br>(PrintSpooler, RBCD)"]
    I --> I4["AppLocker Bypass<br>(InstallUtil, regsvr32)"]
    
    I --> J{New Host Compromised?}
    J -->|Yes| K[Repeat Enumeration]
    J -->|No| C
    
    K --> L{DA Privileges?}
    L -->|Yes| M[Domain Dominance]
    L -->|No| F
    
    M --> M1["NTDS.dit Extraction<br>(secretsdump, vssadmin)"]
    M --> M2["Golden Ticket<br>(mimikatz /ptt)"]
    M --> M3["Trust Abuse<br>(SID History, Forest Trusts)"]
    M --> N[Post-Exploitation]
    
    N --> N1["Data Collection<br>(FileZilla, rclone)"]
    N --> N2["Backdooring<br>(SSH Keys, GPOs)"]
    N --> N3["Log Manipulation<br>(wevtutil, clearev)"]
    N --> Z([End])
    
    style A fill:#2ecc71,stroke:#27ae60
    style C fill:#3498db,stroke:#2980b9
    style Z fill:#e74c3c,stroke:#c0392b
    style M fill:#f39c12,stroke:#d35400
```



# Cheatsheet
```powershell
# Windows/AD Enumeration Cheatsheet
# Post-Exploitation PowerShell Commands

## SYSTEM INFORMATION
# OS and version details
systeminfo
Get-ComputerInfo | Select-Object OsName,OsVersion,OsArchitecture

# Hostname and domain
hostname
[System.Net.Dns]::GetHostName()
(Get-WmiObject Win32_ComputerSystem).Domain
net user /domain
net user {username} /domain
net group /domain
net group "group name" /domain


# Uptime
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object LastBootUpTime

## USER AND GROUP ENUMERATION
# Current user context
whoami
whoami /priv
whoami /groups

# Local users
Get-LocalUser | Format-Table Name,Enabled,LastLogon
Get-WmiObject -Class Win32_UserAccount | Format-Table Name,Disabled,Status

# Local groups
Get-LocalGroup | Format-Table Name
Get-LocalGroupMember -Group "Administrators" | Format-Table Name,PrincipalSource

## NETWORK CONFIGURATION
# IP addresses and interfaces
Get-NetIPConfiguration | Format-List
Get-NetIPAddress | Format-Table IPAddress,InterfaceAlias

# Network connections
Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} | Format-Table LocalAddress,LocalPort,RemoteAddress,RemotePort,State

# DNS cache
Get-DnsClientCache | Format-Table EntryName,Data

## PROCESS AND SERVICE ENUMERATION
# Running processes
Get-Process | Format-Table Id,Name,Path
Get-WmiObject Win32_Process | Select-Object Name,ProcessId,CommandLine

# Services
Get-Service | Where-Object {$_.Status -eq 'Running'} | Format-Table Name,DisplayName,StartType
Get-WmiObject Win32_Service | Select-Object Name,PathName,StartName | Where-Object {$_.PathName -notlike "C:\Windows*"}

## SCHEDULED TASKS
Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'} | Format-Table TaskName,TaskPath,State
Get-WmiObject -Namespace "Root\Microsoft\Windows\TaskScheduler" -Class MSFT_ScheduledTask

## INSTALLED SOFTWARE
# Installed programs
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Format-Table
Get-WmiObject -Class Win32_Product | Select-Object Name,Version

# Patches and updates
Get-HotFix | Sort-Object InstalledOn -Descending | Format-Table HotFixID,InstalledOn

## FILE SYSTEM ENUMERATION
# Interesting files
Get-ChildItem -Path C:\ -Include *pass*,*cred*,*config* -File -Recurse -ErrorAction SilentlyContinue | Select-Object FullName

# Recent files
Get-ChildItem -Path C:\Users\ -Filter *.txt,*.ps1,*.bat,*.vbs -Recurse -ErrorAction SilentlyContinue -File | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | Select-Object FullName

## ACTIVE DIRECTORY ENUMERATION
# Basic domain info
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Domain users
([adsisearcher]"objectCategory=User").FindAll() | ForEach-Object {$_.Properties}

# Domain groups
([adsisearcher]"objectCategory=Group").FindAll() | ForEach-Object {$_.Properties.name}

# Domain computers
([adsisearcher]"objectCategory=Computer").FindAll() | ForEach-Object {$_.Properties.name}

## CREDENTIAL HUNTING
# Saved credentials
cmdkey /list

# Auto-logon credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword

# PowerShell history
Get-Content (Get-PSReadlineOption).HistorySavePath

## PRIVILEGE ESCALATION CHECKS
# Unquoted service paths
Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -like "* *" -and $_.PathName -notlike '"*"*'} | Select-Object Name,PathName

# Service permissions
Get-WmiObject -Class Win32_Service | Where-Object {$_.StartName -match "LocalSystem|LocalService|NetworkService" -eq $false} | Select-Object Name,StartName

## SHARE ENUMERATION
# Local shares
Get-SmbShare | Format-Table Name,Path,Description

# Network shares
net view \\localhost /all
Get-WmiObject -Class Win32_Share | Format-Table Name,Path,Description

## REGISTRY ENUMERATION
# Autoruns
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# LSA secrets check
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "JD"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Skew1"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Data"

## MISC CHECKS
# RDP settings
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections

# PowerShell version
$PSVersionTable.PSVersion

# AMSI bypass check
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').GetValue($null)
```
