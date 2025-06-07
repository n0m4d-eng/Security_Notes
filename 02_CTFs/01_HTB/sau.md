## given info

ip: 10.10.11.224

## steps

1. nmap
2. http service is open on port 55555
3. google request-baskets v 1.2.1 to find an ssrf vuln
4. forward the requests to the exploit and this leads to the filtered http service on port 80
5. look for maltrail v0.53 to find an RCE exploit on there.
6. open netcat, and listen for a reverse shell
7. upgrade shell
8. use `sudo -l` to check permissions, and you can use /systemctl without a password
9. Run that, and from within, try to execute commands with `!`

## findings

1. open ports
    - tcp/20 ssh
    - txp/55555 http - golang net/http server

## creds

## flags

1. user.txt: 9201bc2620edaf7636db7890fe471292
2. root.txt: 3aa9a311eb834996b386c0af77f46843