# System Information

## Kernel Information

```bash
uname -a
```

## Operating System Information

```bash
cat /etc/issue
cat /etc/*-release
```

## View $PATH

```bash
echo $PATH | tr ":" "\n"
```

# Network Configuration

## View IP Configuration Information

```bash
ifconifg -a
```

## Print Current Network Routes

```bash
route -n
```

## Check DNS Resolver

```bash
cat /etc/resolv.conf
```

## View ARP Table

```bash
arp -en
```

## List All Active TCP and UDP Connections

```bash
netstat -auntp

ss -twurp
```

## Dump Clear Text PSK Keys from the Network Manager.

```bash
cat /etc/NetworkManager/system-connections/* |grep -E "^id|^psk"
```

# User Information

## Current User

```bash
id
```

```bash 
grep $USER /etc/passwd
```

## Last Logged on

```bash
lastlog | grep -v '**Never logged in**' 
```

## Currently Logged on User

```bash
w
```

## All Users with UID and GUID Information

```bash
for user in $(cat /etc/passwd | cut -f1 -d ":"); do id $user; done
```

## List All Root Accounts

```bash
cat /etc/passwd |cut -f1,3,4 -d":" | grep "0:0" |cut -f1 -d":" |awk '{print $1}'
```

# Running Processes

## List Running Processes

```bash
ps auxwww
```

## Processes Running as Root

```bash
ps -u root
```

## Processes Running as Current User

```bash
ps -u $USER
```

# File and Folder Permissions

## Can We Read Shadow?

```bash
cat /etc/shadow
```

## Find Sticky Bit

```bash
find / -perm -1000 -type d 2>/dev/null
```

## Find SUID

```bash
find / -perm -u=s -type f 2>/dev/null 
```

## Find SGID

```bash
find / -perm -g=s -type f 2>/dev/null
```

## World Writeable Files

```bash
find -perm -2 type -f 2>/dev/null   
```

## List Configuration Files in /etc/

```bash
ls -al /etc/*.conf
```

## Grep for Interesting Keywords in Configuration Files

```bash
grep 'pass*' /etc/*.conf 2> /dev/null
grep 'key' /etc/*.conf 2> /dev/null
grep 'secret' /etc/*.conf 2> /dev/null
```

## Can We List the Contents of root/?

```bash
ls -als root/
```

## Can We Read other Users History Files?

```bash
find /* -name *.*history* -print 2> /dev/null 
```

# Cronjobs and Scheduled Tasks

```bash
cat /etc/crontab  
ls -als /etc/cron.*
```

## Check for Tasks that Are Run as Root and Are World Writeable.

```bash
find /etc/cron* -type f -perm -o+w -exec ls -l {} \; 
```

# Metasploit Modules

## Post Exploit Enumeration

```bash
post/linux/gather/enum_configs
post/linux/gather/enum_system
post/linux/gather/enum_network
post/linux/gather/enum_psk
post/linux/gather/hashdump
post/linux/gather/openvpn_credentials
post/linux/gather/phpmyadmin_credsteal 
```

# Unsecured Files

## Search by Filetype

```bash
find / -type f \( -iname \*.txt\* -o -iname \*.log\* -o -iname \*.ps1\* -o -iname \*.exe\* -o -iname \*.ini\* -o -iname \*.kdbx\* -o -iname \*.pdf\* -o -iname \*.xls\* -o -iname \*.xlsx\* -o -iname \*.doc\* -o -iname \*.docx\* \) 2> /dev/null
```