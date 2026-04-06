# Windows Remote Management (RDP / WinRM / WMI)

### What brings you here

Port 3389 (RDP) or 5985/5986 (WinRM) is open. These are execution services — you need credentials (or a hash) to use them.

### What did you find?

| Finding                        | Next action                                |
| ------------------------------ | ------------------------------------------ |
| Valid credentials + RDP open   | `xfreerdp /u:<user> /p:<pass> /v:<IP>`     |
| Valid credentials + WinRM open | `evil-winrm -i <IP> -u <user> -p '<pass>'` |
| NTLM hash + WinRM              | `evil-winrm -i <IP> -u <user> -H <hash>`   |
| NTLM hash + RDP                | `xfreerdp /u:<user> /pth:<hash> /v:<IP>`   |
| WMI accessible                 | `wmiexec.py <domain>/<user>:<pass>@<IP>`   |

### Dead ends

- RDP/WinRM open but no credentials → return after finding creds on another service
- NLA required on RDP → valid domain credentials needed

## → Where to go next

- Got a shell → [../post_exploitation/index.md](../post_exploitation/index.md)
- Have hash but no plaintext → [lateral_movement.md](../post_exploitation/lateral_movement.md) for PtH
- Nothing worked → [../STUCK.md](../STUCK.md)

---

```yaml
tags:
  - cpts
  - cybersecurity
  - info gathering
```

# Cheat Sheet

```shell
# RDP
# TCP/UDP port 3389

# Nmap RDP service
nmap -sV -sC {target ip} -p3389 --script rdp*

# Initiate RDP session
rdesktop -u <username> <IP>
xfreerdp /u:username /p:password /v:target ip

# Nmap WinRM
nmap -sV -sC target_ip -p5985,5986 --disable-arp-ping -n

# Interact with WinRm with creds using evil winrm
evil-winrm -i 10.129.201.248 -u Cry0l1t3 -p P455w0rD!

#
```

# Concepts

- The main components used for remote management of Windows and Windows servers are the following:
  - Remote Desktop Protocol (`RDP`)
  - Windows Remote Management (`WinRM`)
  - Windows Management Instrumentation (`WMI`)

# RDP

- The [Remote Desktop Protocol](https://docs.microsoft.com/en-us/troubleshoot/windows-server/remote/understanding-remote-desktop-protocol) (`RDP`) is a protocol developed by Microsoft for remote access to a computer running the Windows operating system

- Uses `TCP port 3389`

- Can also use `UDP 3389 for remote administration`

- To establish a session, **both network firewall and server firewall should allow connections from the outside**

- If Network Address Translation (NAT) is used, the remote computer needs the server's public IP address. Port forwarding must also be set up on the NAT router in the direction of the server

- RDP has handled Transport Layer Security (TLS/SSL) since windows Vista.

## Footprinting

#### NMap

```shell-session
nmap -sV -sC 10.129.201.248 -p3389 --script rdp*
```

Additionally, `--packet-trace` can be used to track the individual packets and inspect their contents manually

### RDP Security Check

#### Installation

 Run `cpan` as root then install the `Encoding::BER` module:

```shell
sudo cpan
cpan[1]> install Encoding::BER
```

#### Usage

```shell
zombear@htb[/htb]$ git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check
zombear@htb[/htb]$ ./rdp-sec-check.pl {target ip}
```

### Initiate RDP Session

Can use `xfreerdp, rdesktop or remmina` to interact with the GUI of the server

```shell
rdesktop -u <username> <IP>
rdesktop -d <domain> -u <username> -p <password> <IP>
xfreerdp [/d:domain] /u:<username> /p:<password> /v:<IP>
xfreerdp [/d:domain] /u:<username> /pth:<hash> /v:<IP> [[Pass]] the hash
```

### Win RM

- Uses TCP ports `5985` (`HTTP`) and `5986` (`HTTPS`)

- Uses Simple Object Access Protocol (SOAP)

```shell
nmap -sV -sC target_ip -p5985,5986 --disable-arp-ping -n
```

### WMI

- Windows Management Instrumentation (WMI)

- Extension of the Common Instrumentation Model (CIM)

- CIM is a core functionality of the standardized Web-Based Enterprise Management (WEBM) for Windows

- WMI allows read/write to almost all the settings on Windows

- Typically accessed by Powershell, VBScript or WMI Console (WMIC)

**Footprinted using WMIexec.py**

```shell
zombear@htb[/htb]$ /usr/share/doc/python3-impacket/examples/wmiexec.py Cry0l1t3:"P455w0rD!"@10.129.201.248 "hostname"

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation[*] SMBv3.0 dialect usedILF-SQL-01
```

# References

[3389 - Pentesting RDP | HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-rdp)

