---
date: 2025-06-10
tags:
  - CTF_Box
  - HTB
OS: Windows
Time Started: 3:40pm
Time Ended: 9.28pm
---


```table-of-contents
```



# Given
```
Driver is an easy Windows machine that focuses on printer exploitation. Enumeration of the machine reveals that a web server is listening on port 80, along with SMB on port 445 and WinRM on port 5985. Navigation to the website reveals that it&amp;amp;amp;#039;s protected using basic HTTP authentication. While trying common credentials the `admin:admin` credential is accepted and we are able to visit the webpage. The webpage provides a feature to upload printer firmwares on an SMB share for a remote team to test and verify. Uploading a Shell Command File that contains a command to fetch a remote file from our local machine, leads to the NTLM hash of the user `tony` relayed back to us. Cracking the captured hash to retrieve a plaintext password we are able login as `tony`, using WinRM. Then, switching over to a meterpreter session it is discovered that the machine is vulnerable to a local privilege exploit that abuses a specific printer driver that is present on the remote machine. Using the exploit we can get a session as `NT AUTHORITY\SYSTEM`.
```

ip/scope: 10.10.11.106



# Steps
How did I solve it



# Findings
- Open ports:
	- HTTP (80), RDP (135), SMB (445), Cloud Witness (5985)
- Visiting the ip on a browser shows a login form.
	- Looking at the login request on `burpsuite` and making an invalid request returns a response where the header references the user `admin`
- Admin panel has weak creds, password is also `admin`



# Creds
- Website creds: `admin:admin`
- User creds from someone accessing the share:

```

TONY::DRIVER:5a42fba6465e871c:577360343d389e60e26eb8a49dcb2c18:0101000000000000eb7df98226dadb01b429baed022872a900000000020000000000000000000000:liltony

```



# Flags
- User: cdaddb5ac0c788cde103cac026c0f089
- Root: c9ee696d29de58aade0081c20e721e62



# Proof
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-10 15:45 +08
Stats: 0:01:42 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 94.79% done; ETC: 15:47 (0:00:06 remaining)
Nmap scan report for 10.10.11.106
Host is up (0.0099s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h38m14s, deviation: 0s, median: 6h38m14s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-06-10T14:25:30
|_  start_date: 2025-06-10T14:21:48
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 152.92 seconds

```
