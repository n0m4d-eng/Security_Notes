---
Started: 11-07-25 | 20:02
Ended: 11-07-25 |
---
#CTF/HTB/Windows/Easy

# Given

Chatterbox is a fairly straightforward machine that requires basic exploit modification or Metasploit troubleshooting skills to complete.

## IP

10.10.10.74

# Steps

1. Rustcsan first to get an idea of the open ports.

```shell
PORT      STATE SERVICE      REASON
135/tcp   open  msrpc        syn-ack ttl 127
139/tcp   open  netbios-ssn  syn-ack ttl 127
445/tcp   open  microsoft-ds syn-ack ttl 127
9255/tcp  open  mon          syn-ack ttl 127
9256/tcp  open  unknown      syn-ack ttl 127
49152/tcp open  unknown      syn-ack ttl 127
49153/tcp open  unknown      syn-ack ttl 127
49154/tcp open  unknown      syn-ack ttl 127
49155/tcp open  unknown      syn-ack ttl 127
49156/tcp open  unknown      syn-ack ttl 127
49157/tcp open  unknown      syn-ack ttl 127
```

2. Next is Nmap

```shell
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
9255/tcp  open  http         AChat chat system httpd
|_http-server-header: AChat
|_http-title: Site doesn't have a title.
9256/tcp  open  achat        AChat chat system
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: CHATTERBOX; OS: Windows; CPE: cpe:/o:microsoft:windows
```

- SMB is running on 445 and 139, along with rpc on 135, and there seems to be an http server on 9255

3. ![](Assets/Pasted%20image%2020250711143309.png)
4. ![](Assets/Pasted%20image%2020250711143328.png)
5. Shifted focus to rpc, but this is about all I can do without credentials
6. ![](Assets/Pasted%20image%2020250711143351.png)
7. I have to turn to `Achat` the service that's running on the http port.
8. I couldn't get the exact version number from enumeration, so I'll try the default achat exploit from exploitdb
9. 

# Creds