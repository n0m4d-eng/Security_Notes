**Started:** 2025-07-18 11:32:19 
**Ended:** 2025-07-18 13:49:02
**Duration:** 0d : 2h : 16m : 43s



# Given Info

This is what HTB says:

> Sunday is a fairly simple machine, however it uses fairly old software and can be a bit unpredictable at times. It mainly focuses on exploiting the Finger service as well as the use of weak credentials.

## IP

10.10.10.76

# Things I Learnt

This machine was a fun one in that I learned about the many ways that I could have gone about doing the privesc portion. I looked through GTFOBins and got a privesc for `wget` before realizing how many other ways I could have gone about it.

[0xdf](https://0xdf.gitlab.io/2018/09/29/htb-sunday.html#privesc-sammy-to-root) has a pretty awesome guide on this that I looked at after the fact. Today I learnt that `wget` could be used in so many ways, and honestly how much more I have to learn in this field.

# Writeup

## Enumeration

I started off with Rustscan to get a quick look at what ports are open, and then Nmap to do a full port scan with scripts and versions. I saw 5 open ports. Something that stood out was Finger(79).

```bash
PORT      STATE SERVICE   REASON
79/tcp    open  finger    syn-ack ttl 59
111/tcp   open  rpcbind   syn-ack ttl 63
515/tcp   open  printer   syn-ack ttl 59
6787/tcp  open  smc-admin syn-ack ttl 59
22022/tcp open  unknown   syn-ack ttl 63
```

*TCP 22022 is running SSH. It didn't show up on Rustscan, but nmap caught it.*

At this point I needed to do some googling about the Finger service. There's a TLDR below:

---

**Finger (TCP 79) TLDR**

A service that provides status updates about logged in users. You can get information such as the username, full name, time and date of their login. It provides this info by accessing a specific user profile in the system’s server, helping to know if someone is available at their terminal.

[Wikipedia](https://en.wikipedia.org/wiki/Finger_(protocol))

---

[Pentestmonkey](https://pentestmonkey.net/tools/user-enumeration/finger-user-enum) has a script available to start pentesting this service, and get all the users who've logged on

```bash
┌──(root㉿n0m4d)-[/host_data]
└─# finger-user-enum.pl -U ./payloads/names.txt -t 10.10.10.76
```

This showed me that there were 3 users on the system. Root, Sammy and Sunny.

![](Assets/Pasted%20image%2020250718135236.png)

*Side note, there was Oracle Solaris running on TCP(6767). I looked up exploits for this, and honestly this didn't seem to lead anywhere. So I went back to the Finger service.*

## Foothold

It was a classic case of using a weak password. Sunnny's password was `sunday`. Which coincidentally is the name of this machine. It worked on the Solaris dashboard, so I figured it might work on SSH. 

It did. running `ssh sunny@10.10.10.76` using `sunday` as the password got me into Sunny's user account. First things first. Checking the `.bash_history` file, ability to run commands as sudo, any file permissions, etc.

From the bash history, I found the user file was located in sammy's home directory. Also there was a nonstandard folder in sunny's home folder (`/backups`).

That had a backup of the shadow file. I grabbed it for some offline cracking.

```bash title="shadow.backup" fold
mysql:NP:::::::
openldap:*LK*:::::::
webservd:*LK*:::::::
postgres:NP:::::::
svctag:*LK*:6445::::::
nobody:*LK*:6445::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
```

I used Hashcat for this. Took a while, but I got it in the end. So now I knew Sammy's password.

![](Assets/Pasted%20image%2020250718144357.png)

And I used that to get into Sammy's account. The user flag was in the home directory.

## Getting Root

This starts with me enumerating the sammy's account.`sudo -l` showed me that sammy could run `wget` as root. Naturally the first thing I did was get on GTFOBins, and look for Wget.

Since the wget binary is allowed to run as superuser, it won't drop its elevated privileges, and could possibly be used to escalate my current access. The idea here is to use wget to run a bit of script that has been written to a variable. This opens up an elevated session as root.

```bash title="wget" fold 
TF=$(mktemp)
chmod +x $TF
echo -e '#!/bin/sh\n/bin/sh 1>&0' >$TF
sudo wget --use-askpass=$TF 0
```

 The root flag is in the home folder.

# Creds

- sunny : sunday
- sammy : cooldude!

# Proof

![](Assets/Pasted%20image%2020250718144608.png)

![](Assets/Pasted%20image%2020250718145026.png)