---
date: 2025-06-09
tags:
  - HTB
  - CFT_Box
OS: Linux
---


```table-of-contents
```



# Given
ip/scope: 10.10.11.28



# Steps
- nmap scan: `nmap -sCV -p- 10.10.11.28 -oN nmap.out`
- manual enumeration of the website to see if there are any exploitable areas like forms, links, etc. Got domain name, and the fact that contact works through php.
- add domain to `/etc/hosts`
- follow contact link to online contact form page.
	- contact form doesn't work, fails to send out anything.
- used feroxbuster to try and check for links/directories that aren't immediately apparent.
- Googled `turboblack 3.2.0 exploit`, and found a known vulnerability (CVE-2023-41425) which seems to reference an XSS vulnerability.
- Googled a bit for the default login for wondercms, and got:
	- `http://sea.htb/loginURL/index.php?page=loginURL`



# Findings
- nmap scan: 
	- open ports: ssh(22), http(80)
	- OS: Linux
- website contact form works on a php file.
- website contact link also has domain name of box, which is `sea.htb`
- most files were off limits, except for:

```
200      GET        1l        1w        6c http://sea.htb/themes/bike/version
200      GET       21l      168w     1067c http://sea.htb/themes/bike/LICENSE
200      GET        1l        9w       66c http://sea.htb/themes/bike/summary
```

- Going into LICENSE, and Summary gives you a theme name and version `turboblack 3.2.0`
- Found exploit that uses xss, and the login url of the site.



# Creds
Creds for privesc/lateral movement
- cms login hash: `$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q`
- Note the escape characters in the hash above
- `$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q:mychemicalromance`



# Flags
- User: 5ef514189276ffb34d7c702441e763f8
- Root: 2b877443cea9411a76939528ee117502



# Proof

## nmap
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-09 20:52 +08
Nmap scan report for 10.10.11.28
Host is up (0.013s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e3:54:e0:72:20:3c:01:42:93:d1:66:9d:90:0c:ab:e8 (RSA)
|   256 f3:24:4b:08:aa:51:9d:56:15:3d:67:56:74:7c:20:38 (ECDSA)
|_  256 30:b1:05:c6:41:50:ff:22:a3:7f:41:06:0e:67:fd:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Sea - Home
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.21 seconds
```


## feroxbuster
```bash
                                                                                                                                                                                                                             
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://sea.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       84l      209w     3341c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        7l       20w      199c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       20w      228c http://sea.htb/data => http://sea.htb/data/
301      GET        7l       20w      230c http://sea.htb/themes => http://sea.htb/themes/
301      GET        7l       20w      232c http://sea.htb/messages => http://sea.htb/messages/
301      GET        7l       20w      231c http://sea.htb/plugins => http://sea.htb/plugins/
301      GET        7l       20w      234c http://sea.htb/data/files => http://sea.htb/data/files/
301      GET        7l       20w      235c http://sea.htb/themes/bike => http://sea.htb/themes/bike/
301      GET        7l       20w      239c http://sea.htb/themes/bike/css => http://sea.htb/themes/bike/css/
200      GET        1l        1w        6c http://sea.htb/themes/bike/version
200      GET       21l      168w     1067c http://sea.htb/themes/bike/LICENSE
404      GET        0l        0w     3341c http://sea.htb/messages/straightstream
200      GET        1l        9w       66c http://sea.htb/themes/bike/summary
404      GET        0l        0w     3341c http://sea.htb/where-to-buy
404      GET        0l        0w     3341c http://sea.htb/messages/raa
404      GET        0l        0w     3341c http://sea.htb/plugins/pageimg
404      GET        0l        0w     3341c http://sea.htb/themes/bike/css/1173
404      GET        0l        0w     3341c http://sea.htb/data/files/gouwu
[####################] - 3m    240021/240021  0s      found:16      errors:3940   
[####################] - 3m     30000/30000   171/s   http://sea.htb/ 
[####################] - 3m     30000/30000   164/s   http://sea.htb/data/ 
[####################] - 3m     30000/30000   177/s   http://sea.htb/themes/ 
[####################] - 3m     30000/30000   169/s   http://sea.htb/messages/ 
[####################] - 3m     30000/30000   171/s   http://sea.htb/plugins/ 
[####################] - 3m     30000/30000   164/s   http://sea.htb/data/files/ 
[####################] - 3m     30000/30000   170/s   http://sea.htb/themes/bike/ 
[####################] - 3m     30000/30000   177/s   http://sea.htb/themes/bike/css/   
```
