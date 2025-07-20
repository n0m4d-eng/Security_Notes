#CTF/HTB/Windows/Easy

# Given

ServMon is an easy Windows machine featuring an HTTP server that hosts an NVMS-1000 (Network Surveillance Management Software) instance. This is found to be vulnerable to LFI, which is used to read a list of passwords on a user&amp;amp;#039;s desktop. Using the credentials, we can SSH to the server as a second user. As this low-privileged user, it&amp;amp;#039;s possible enumerate the system and find the password for `NSClient++` (a system monitoring agent). After creating an SSH tunnel, we can access the NSClient++ web app. The app contains functionality to create scripts that can be executed in the context of `NT AUTHORITY\SYSTEM`. Users have been given permissions to restart the `NSCP` service, and after creating a malicious script, the service is restarted and command execution is achieved as SYSTEM.

## IP

10.10.10.184

# Steps

## Enumeration

- The first thing to do was to run scans on nmap and rustscan. I wanted to check out the open ports, as well as the services that were running on this target.

```shell fold title=rustscan
PORT        SERVICE          
21/tcp      ftp    
22/tcp      ssh    
80/tcp      http    
135/tcp     msrpc    
139/tcp     netbios-ssn  
445/tcp     microsoft-ds 
5666/tcp    nrpe    
6063/tcp    x11    
6699/tcp    napster          
8443/tcp    https-alt        
49664/tcp   unknown          
49665/tcp   unknown          
49666/tcp   unknown          
49667/tcp   unknown          
49668/tcp   unknown          
49669/tcp   unknown          
49670/tcp   unknown  
```

- There are a few ports of interest, namely:
	- FTP(21)
	- SMB(445)
	- HTTP(80)
	- RPC(135)
- Of these, FTP and SMB might allow anonymous logins, so we start with FTP.
- A quick check shows that we can connect with an anonymous account, and going through the files, we have a directory called `Users` where we end up getting two names for our list, the location of some passwords, and a to-do list.

![](Assets/Pasted%20image%2020250709091418.png)

## Exploit

- Port 80 is running the NVMS-1000 network monitoring system's web UI. And this piece of software happens to be vulnerable to Local File Inclusion. So I fired up Burpsuite, and start looking at how the login system works. Turns out I can use that API call to expose files on the system. 

![](Assets/Pasted%20image%2020250709092024.png)

- Making use of the LFI vulnerability gets me to Nathan's desktop, and that list of passwords Nadine left him.

![](Assets/Pasted%20image%2020250709094521.png)

- The next step would be to test the SMB(445) service. It didn't seem to allow guest logins, so I figured I'd brute force the passwords list against both usernames. One of them stuck.

![](Assets/Pasted%20image%2020250709235454.png)

- There wasn't much to see here, so I decided to try my luck with SSH. Hopefully nadine had reused the same password.

![](Assets/Pasted%20image%2020250709235435.png)

- The password was indeed reused. And now we've gotten a foothold onto the machine.

![](Assets/Pasted%20image%2020250709095016.png)

## Foothold

- Now that a foothold was established, I could get to Nadine's desktop and pull out the user flag.
- Next, I started to enumerate the system. I started doing some local enumeration based on this checklist: [viperone](https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/privilege-escalation/privilege-escalation-checklist) . Got a whole lot of Access Denied.
- After that, I ended up looking through the file system for anything that stood out, or didn't belong.
- There was a program called NSClient++. That definitely wasn't default.

![](Assets/Pasted%20image%2020250709112408.png)

## Escalation

- First thing to do was to get more info on the NSClient application. Running it on the terminal gave me some help. Enough to get the version number that got me to an interesting CVE (CVE-2019-20085)

```bash
NSClient++, version: 0.5.2.35 2018-01-28, Platform: x64
```

- Using `searchsploit` got me a neat POC on how I could execute arbitrary code on as the local system admin through this application.
	- ExploitDB has it [here](https://www.exploit-db.com/exploits/46802)
- This required getting the default password for the web UI for starters. I got that from`txtc:\program files\nsclient++\nsclient.ini`
- And using this, and a netcat listener... I had a reverse shell as the local admin.

![](Assets/Pasted%20image%2020250709231448.png)

# Creds

- Nathan passwords.txt file

```plaintext
1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$
```

- Nadine: L1k3B1gBut7s@W0rk
- Default password for NSClient++ : ew2x6SsGTxjRwXOT

# Proof

![](Assets/Pasted%20image%2020250710001414.png)