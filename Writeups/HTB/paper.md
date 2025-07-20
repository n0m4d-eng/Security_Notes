## Given Info

10.10.11.143

## Steps

1. nmap
2. check out the site on port 80, ad its just a basic landig page for centOS
3. checking the network log when it loads, shows 403 for some reason, not 200. Alternatively run 'banner-plus' to check the banner grabs from nmap.
4. there's an extra header called X-Backend-Server, which seems to leak the domain office.paper
5. fuzzing for subdomains gives one hit called chat
6. directory fuzzing with ferox, or gobuster doesn't yield much
7. wpscan on this domain shows some vulns for office.paper's wordpress cms
8. dump the posts to get the secret employee reg link, and create and account on there.
9. after logging into the chat, notice that there is a bot called recyclops
10. the bot is allowed to read files, and traverse the directory structure.
11. look at the passwd file, some of the files in the proc directory, and maybe try to run some commands. The bot has some command injection hardening.
12. found the bots' env file, and found some creds for dwight. The assumption here is that the bot is running using dwitght's account.
13. ssh into dwight's account, and then start exploring.
14. run linpeas on dwight's machine and there's a vulnerability it finds - CVE-2021-3560
15. this vuln creates a new user with root privs using the policy kit (polkit)
16. switch to the new user, and run `sudo -l` to check privs
17. run `sudo su -` to change to root

## Findings

1. open ports: ssh/22, http/80, https/443
2. found x-backend-server = office.paper
3. found wp version 5.2.3, and exploit
4. found vuln for wp version and dumped posts to get the employee reg link
5. found the bot's env during file traversal
6. found the user.txt file
7. linpeas finds a vuln cve-2021-3560
8. found root.txt

## Creds

1. 

<!=====Contents of file ../hubot/.env=====>

export ROCKETCHAT_URL='[http://127.0.0.1:48320](http://127.0.0.1:48320/)'

export ROCKETCHAT_USER=recyclops

export ROCKETCHAT_PASSWORD=Queenofblad3s!23

export ROCKETCHAT_USESSL=false

export RESPOND_TO_DM=true

export RESPOND_TO_EDITED=true

export PORT=8000

export BIND_ADDRESS=127.0.0.1

<!=====End of file ../hubot/.env=====>