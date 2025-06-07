## given info

10.10.11.189

## steps

1. nmap scan 1.1 http server on tcp/80 running nginx 1.18.0 1.2 domain name seems to be [](http://precious.htb/)[http://precious.htb](http://precious.htb) 1.3 ssh open on tcp/22 OpenSSH 8.4p1 Debian 5+deb11u1
2. http server tech stack 2.1 nginx 1.18.0 2.2 phusion passenger 6.0.15
3. used ffuf and gobsuter - no subdomains/subdirectories
4. tested the funcitonality of the input form against regular sites like google, but it wouldn't work
5. started a python server on a local dir and gave it ([](http://10.10.14.17:8000/)[http://10.10.14.17:8000](http://10.10.14.17:8000)). This worked, and a PDF file was downloaded.
6. the pdf metadata showed that this was created by the module pdfkit.
7. there's a vuln for pdfkit CVE-2022-25765, and there's a command injection and reverse shell POC.
8. ran the POC, and got a shell onto the web server.
9. snooping around the webserver in proc, .bash_history, the pdfapp files didn't yield anything.
10. there's a file named .bundle that seems out of place.
11. found some creds here for henry.
12. used henry's creds to ssh into the host.
13. sudo -l shows that he can run /usr/bin/ruby, and /opt/update_dependencies.rb as sudo
14. we can view the update_dependencies.rb file, and this shows that there's some vulnerable code running here in the `yaml.load` part that refers to YAML deserialization
15. we use a POC from "[](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Ruby.md#yaml-deserialization)[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure) Deserialization/Ruby.md#yaml-deserialization".
16. we download the yaml file, and run the poc with `sudo /usr/bin/ruby /opt/update_dependenceies.rb` in the same folder. It should show a lot, but there will be an id command that's been run somewhere in there, showing us that the code ran as root.
17. then we change the code in the yaml file to copy out bash and give it executable permissions: `cp /bin/bash /tmp/shaco; chmod 6777 /tmp/shaco`
18. from here, we run `sudo /tmp/shaco -p`, and it should give us a root shell with a new UID

## creds

1. /home/ruby/.bundle -> henry:Q3c1AqGHtoI0aXAYFH

## flags

1. user.txt -> 1bd9b813ea65b2a00dfcb379f72eceff
2. root.txt -> 59632985bce147e85d5b684c27badb7c