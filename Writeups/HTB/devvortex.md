# Given

10.10.11.242

# Steps

1. nmap scan
2. check out the website on port 80
3. ffuf for subdomains
4. dev.devvortex.htb is another boilerplate site.
5. ferox for other pages, maybe hidden ones
6. gobuster for more directory enum
7. google for joomla default version file location, and there'a public link to joomla's manifest
8. google for exploits to thtat version
9. use this to get the logon to the admin panel in plaintext
10. login to the admin panel
11. check site structure for editable files to drop in a php reverse shell
12. connect to it and use the mysql command to access the site db
13. go to the joomla table, and then find the users table. there's creds there for lewis and logan and hashed passwords
14. use hashcat, or an online hash decrypt to translate the hashes into plaintext
15. use logans creds to ssh into the machine as logan.
16. check logan's access with `sudo -l` and see he has access to apport-cli
17. create a dummy report for it to work with ( by starting up and killing a process) and then run apport-cli as sudo
18. when this generates a report, it uses less. less can run commands like vim, and has root access.
19. when the report is generated in less, run `!/bin/bash`, and you should be able to break out, and into a root shell.
20. use this to roam the system and find the root flag.

# Findings

1. open ssh (tcp/22) and open http (tcp/80)
2. ffuf found subdomain dev.devvortex.htb
3. found /administrator dir, and that led to joomla landing page for admin login
4. joomla 4.2.6 has an info disclosure vuln
5. found creds in plaintext
6. found usernames and passwords from the db
7. found file called user.txt in logan's home dir

# Creds

DB/CMS

DB: joomla

DB type: mysql

host: localhost

user: lewis

password: P4ntherg0t1n5r3c0n##

1. creds from db

lewis: P4ntherg0t1n5r3c0n##

logan: tequieromucho

1. 

# Flags

1. logan flag: ce92f60c0b9f228d62a65efa9c1254c7
2. root flag: 68bbb9909eb286758c0d9548400ba731