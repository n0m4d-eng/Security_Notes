```yaml
tags:

- cpts
- cybersecurity
- info gathering
```

# Cheat Sheet

```shell
# SSH Audit
git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
./ssh-audit.py {target ip}

# SSH with preferred auth method
ssh -v user@10.129.14.132 -o PreferredAuthentications=password

# Rsync uses TCP port 873
# Use netcat if you find an rsync service when you scan with nmap.

# Netcat Probe for accessible shares
nc -nv {target ip} 873

# Enumerating open shares
rsync -av --list-only rsync://{target ip}/dev

# Sync all files to the attack machine
rsync -av rsync://{target ip}/dev

# Rsync over SSH
rsync -a {source folder} {SSH Username}@{target ip}:{destination path}

# Nmap R-services
sudo nmap -sV -p 512,513,514 {target ip}

# The hosts.equiv file is recognized as the global configuration regarding all users on a system,
# The .rhosts provides a per-user configuration.

# Loggin in using Rlogin
rlogin {target ip} -l {username we get from rhosts file}
```

# Concepts

- Methods and protocols for managing servers remotely

### SSH

- Secure Shell (SSH)

- `TCP port 22`

- Runs on all common operating systems

- OpenBSD SSH (OpenSSH) is an open source fork of the original, commercial SSH from SSH Communications Security

- Two competing protocols `SSH-1` and `SSH-2`

- SSH-2 is more advanced in terms of encryption, speed, stability and security

- Open SSH has six different auth methods:
  
  - Password authentication
  
  - Public-key authentication
  
  - Host-based authentication
  
  - Keyboard authentication
  
  - Challenge-response authentication
  
  - GSSAPI authentication

### Public Key Auth

- A client-side auth method using a `private and public key pair`

- Private keys are stored on the client's machine and are secret. To connect to SSH, we have to enter a password, giving the protocol access to the private key

- Public keys are also stored on the server. The server use its **public key to create a cryptographic problem that the client side has to solve using their private key**

## Default Configuration

Config for the OpenSSH server is located in the `sshd_config` file. 

```shell
cat /etc/ssh/sshd_config  | grep -v "#" | sed -r '/^\s*$/d'
```

## Dangerous Settings

| **Setting**                  | **Description**                             |
| ---------------------------- | ------------------------------------------- |
| `PasswordAuthentication yes` | Allows password-based authentication.       |
| `PermitEmptyPasswords yes`   | Allows the use of empty passwords.          |
| `PermitRootLogin yes`        | Allows to log in as the root user.          |
| `Protocol 1`                 | Uses an outdated version of encryption.     |
| `X11Forwarding yes`          | Allows X11 forwarding for GUI applications. |
| `AllowTcpForwarding yes`     | Allows forwarding of TCP ports.             |
| `PermitTunnel`               | Allows tunneling.                           |
| `DebianBanner yes`           | Displays a specific banner when logging in. |

## Footprinting

### SSH Audit

- Check the client and server side config using `ssh-audit`.
- ```shell
  git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
  ./ssh-audit.py {target ip}
  ```



### Rsync

- Tool for locally and remotely copying files.

- TCP port `873`

- Well known for the `delta-transfer algorithm`

- The algorithm reduces the amount of data transmitted over the network when there's a local version of the file on the destination host

- Basically it only transfers the difference between the source and the destination.



Scan for Rsync on target using:

```shell-session
sudo nmap -sV -p 873 {target ip}
```

Probe for accessible shares using Netcat

```shell-session
nc -nv {target ip} 873
```



### R-Services

- Suite of services hosted to enable remote access or issue commands between **Unix hosts over TCP/IP**

- R-services was the standard till SSH came along

- R-services is similar to telnet, and transfers files **in an unencrypted format**

- Vulnerable to Man In The Middle (MITM) attacks

- Uses `TCP ports 512, 513, 514`

- **Only accessible through a suite of programs called r-commands**



#### R-Commands suite

- rcp (`remote copy`)
- rexec (`remote execution`)
- rlogin (`remote login`)
- rsh (`remote shell`)
- rstat
- ruptime
- rwho (`remote who`)



#### Most common R-Commands

| **Command** | **Service Daemon** | **Port** | **Transport Protocol** | **Description**                                                                                                                                                                                                                                                            |
| ----------- | ------------------ | -------- | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `rcp`       | `rshd`             | 514      | TCP                    | Copy a file or directory bidirectionally from the local system to the remote system (or vice versa) or from one remote system to another. It works like the `cp` command on Linux but provides `no warning to the user for overwriting existing files on a system`.        |
| `rsh`       | `rshd`             | 514      | TCP                    | Opens a shell on a remote machine without a login procedure. Relies upon the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files for validation.                                                                                                                 |
| `rexec`     | `rexecd`           | 512      | TCP                    | Enables a user to run shell commands on a remote machine. Requires authentication through the use of a `username` and `password` through an unencrypted network socket. Authentication is overridden by the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files. |
| `rlogin`    | `rlogind`          | 513      | TCP                    | Enables a user to log in to a remote host over the network. It works similarly to `telnet` but can only connect to Unix-like hosts. Authentication is overridden by the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files.                                     |



#### Hosts.equiv File

- The /etc/hosts.equiv file contains a list of trusted hosts and is used to grant access to other systems on the network.

- When users on one of these hosts try to access the system, they are **granted access with no futher authentication**



```shell
cat /etc/hosts.equiv
```



### Footprinting with Nmap

```shell
sudo nmap -sV -p512-514 {tareget ip}
```



### Checking out Rhosts file

```shell
zombear@htb[/htb]$ cat .rhosts

htb-student     10.0.17.5
+               10.0.17.10
+               +
```



### Loggin in using Rlogin

```shell
rlogin {target ip} -l {username we get from rhosts file}
```



### List authenticated users using Rwho

```shell
zombear@htb[/htb]$ rwho

root     web01:pts/0 Dec  2 21:34
htb-student     workstn01:tty1  Dec  2 19:57  2:25      
```

**the rwho daemon periodically broadcasts information about logged-on users, so it might be beneficial to watch the network traffic.**



### List authenticated users using Rusers

```shell
zombear@htb[/htb]$ rusers -al 10.0.17.5

htb-student     10.0.17.5:console          Dec 2 19:57     2:25
```





# References

[873 - Pentesting Rsync | HackTricks](https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync)