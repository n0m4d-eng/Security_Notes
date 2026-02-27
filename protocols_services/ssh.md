**Nmap Scripting scan**

```bash
nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 [IP]
```

**Enumeration**

```bash
ftp -A [IP]
ftp [IP]

# Login with anonymous credentials
anonymous:anonymous

# Upload a test file to check for reflection on an HTTP port
put test.txt
```

**Upload binaries**

```bash
ftp> binary

ftp> put [binary_file]
```

**Downloading files recursively**

```bash
wget -r ftp://[user]:[password]@[IP]/

# Searching for specific file
find / -name [filename_pattern] 2>/dev/null

# Example of searching for files
find / -name Settings.*  2>/dev/null
```

**Brute Force**

```bash
hydra -l [username] -P [path_to_wordlist] [IP] -t 4 ftp
```

**Passive Mode Syntax**

```bash
ftp -p [IP]
```