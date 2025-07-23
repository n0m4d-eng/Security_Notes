---
tags:
  - Footprinting
  - Enumeration
  - FTP
---

# Cheat Sheet

| **Code**                                                   | **Description**                                                                                                                                                   |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sudo nmap -sV -p21 -sC -A 10.129.14.136`                  | using nmap to footprint the ftp service whic hruns on default port 21, usinge the aggressive scan (-A), verison scan (-sV), and scripts scan (-sC).               |
| ` nc -nv 10.129.14.136 21`                                 | connecting to the ftp service on p21 using netcat                                                                                                                 |
| `telnet 10.129.14.136 21`                                  | connecting to the ftp service on p21 using telnet                                                                                                                 |
| `openssl s_client -connect 10.129.14.136:21 -starttls ftp` | Same thing with openssl, for FTP servers running on TLS/SSL encryption. Plus point is that we can see the SSL certificates.HTB{b7skjr4c76zhsds7fzhd4k3ujg7nhdjre} |

## FTP

- File Transfer Protocol
- Runs within the application layer of the TCP/IP protocol stack. Same as HTTP/POP.
- Commands are sent on `TCP Port 21`
- Data is exclusively sent on `TCP Port 20`
- Is a `clear text protocol` meaning **sniffing is possible**
- Alternatively, the server might offer **anonymous FTP**
- [FTP Commands](<(https://www.serv-u.com/ftp-server-windows/commands)>)

## TFTP

- Trivial File Transfer Protocol.

- Does not provide user authentication

- Uses UDP instead of TCP.

- Uses UDP assisted application layer recovery.

- Commands:
  
  | **Commands** | **Description**                                                                                                                        |
  | ------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
  | `connect`    | Sets the remote host, and optionally the port, for file transfers.                                                                     |
  | `get`        | Transfers a file or set of files from the remote host to the local host.                                                               |
  | `put`        | Transfers a file or set of files from the local host onto the remote host.                                                             |
  | `quit`       | Exits tftp.                                                                                                                            |
  | `status`     | Shows the current status of tftp, including the current transfer mode (ascii or binary), connection status, time-out value, and so on. |
  | `verbose`    | Turns verbose mode, which displays additional information during file transfer, on or off.                                             |

## Default Config

- One of the most used FTP servers on Linux based distros: `vsFTPd`.

- Default configuration is in `/etc/vsftpd.conf`

- ```shell-session
  cat /etc/vsftpd.conf | grep -v "#"
  ```

## FTPUsers

- File that is used to deny certain users access to the FTP service.

- ```shell-session
  cat /etc/ftpusers
  ```

## Dangerous Settings

| **Setting**                    | **Description**                                                                                                                                                             |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `anonymous_enable=YES`         | Allowing anonymous login?                                                                                                                                                   |
| `anon_upload_enable=YES`       | Allowing anonymous to upload files?                                                                                                                                         |
| `anon_mkdir_write_enable=YES`  | Allowing anonymous to create new directories?                                                                                                                               |
| `no_anon_password=YES`         | Do not ask anonymous for password?                                                                                                                                          |
| `anon_root=/home/username/ftp` | Directory for anonymous.                                                                                                                                                    |
| `write_enable=YES`             | Allow the usage of FTP commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE?---<br/><br/>tags:<br/><br/>cpts<br/><br/>cybersecurity<br/><br/>enumeration<br/><br/>--- |
