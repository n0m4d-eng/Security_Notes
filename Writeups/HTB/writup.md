## Given Info

10.10.10.138

## Steps

1. nmap scan shows open ssh (tcp/22) and http (tcp/80)
2. visiting the link on the browser gives some info about the site's DOS protection
3. the nmap report shows that there's a disallowed link called /writeup/
4. going to that link shows us an incomplete blog site run with CMS Made Simple
5. default creds didn't work
6. looking through the page, there's a line with the copyright for the cms.
7. googleing the cms, and the year given shows a whole bunch of vulnerabilities.
8. check out the code for the CMS made simple site, and there's a file structure given.
9. try out the file structure on the machine's url, and you'll get to the changelog for this implementation.
10. this gives us the version of the cms used, which helps us to pick the exploit we need.
11. logging into the cms isn't going to work, so we ssh into the machine
12. once there, we can take the user flag.
13. we look for any vulnerablities manually, but can't find much so we use linenum/linpeas
14. one of the groups that jkr belongs to is called "staff" which is a non-standard one.
15. googlin 'staff' under Debian groups gives us its ablity to run things off the system PATH.
16. in order to hijack the path (path injection), we have to find a process that calls the path binaries using a relative path
17. to do this, we have to use a process monitor, and then see what processes are run with a relative path that requires the system to access the $PATH variable

## Creds

1. from sqli: un: jkr email: jkr@writeup.htb pass-hash: 62def4866937f08cc13bab43bb14e6f7 pass: raykayjay9

## Flags

1. user.txt - 18f086fbfd2e455097675e0aeb66c95c
2. root.txt - ye48a0b992edc9538b09c7d808bbf3d19