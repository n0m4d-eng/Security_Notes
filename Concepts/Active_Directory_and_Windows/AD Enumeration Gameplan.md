---
date: 
tags:
  - ActiveDirectory
  - Windows
---

```table-of-contents
```

---

# What is AD?

- Directory service for Windows enterprise
- Based on x500 and LDAP
- Distributed, hierarchical structure allowing centralized management of org’s resources (users, groups, network devices, file shares, trusts).
- Provides `authentication, accounting and authorization` functions withing the enterprise environment.

# External Recon and Enumeration Principles

## Purpose Served

**Understanding the lay of the land**

- Validating information provided to you in the scoping document from the client
- Ensuring you are taking actions against the appropriate scope when working remotely
- Looking for any information that is publicly accessible that can affect the outcome of your test, such as leaked credentials

## What Are We Looking For?

| **Data Point** | **Description**                                                   |
| -------------- | ----------------------------------------------------------------- |
| `IP Space`     | Valid ASN for our target, netblocks in use for the organization's public-facing infrastructure, cloud presence and the hosting providers, DNS record entries, etc. |
| `Domain Information` | Based on IP data, DNS, and site registrations. Who administers the domain? Are there any subdomains tied to our target? Are there any publicly accessible domain services present? (Mailservers, DNS, Websites, VPN portals, etc.) Can we determine what kind of defenses are in place? (SIEM, AV, IPS/IDS in use, etc.) |
| `Schema Format` | Can we discover the organization's email accounts, AD usernames, and even password policies? Anything that will give us information we can use to build a valid username list to test external-facing services for password spraying, credential stuffing, brute forcing, etc. |
| `Data Disclosures` | For data disclosures we will be looking for publicly accessible files ( .pdf, .ppt, .docx, .xlsx, etc. ) for any information that helps shed light on the target. For example, any published files that contain `intranet` site listings, user metadata, shares, or other critical software or hardware in the environment (credentials pushed to a public GitHub repo, the internal AD username format in the metadata of a PDF, for example.) |
| `Breach Data` | Any publicly released usernames, passwords, or other critical information that can help an attacker gain a foothold. |

## Where Are We Looking?

| **Resource** | **Examples** |
| --- | --- |
| `ASN / IP registrars` | [IANA](https://www.iana.org/), [arin](https://www.arin.net/) for searching the Americas, [RIPE](https://www.ripe.net/) for searching in Europe, [BGP Toolkit](https://bgp.he.net/) |
| `Domain Registrars & DNS` | [Domaintools](https://www.domaintools.com/), [PTRArchive](http://ptrarchive.com/), [ICANN](https://lookup.icann.org/lookup), manual DNS record requests against the domain in question or against well known DNS servers, such as `8.8.8.8`. |
| `Social Media` | Searching Linkedin, Twitter, Facebook, your region's major social media sites, news articles, and any relevant info you can find about the organization. |
| `Public-Facing Company Websites` | Often, the public website for a corporation will have relevant info embedded. News articles, embedded documents, and the "About Us" and "Contact Us" pages can also be gold mines. |
| `Cloud & Dev Storage Spaces` | [GitHub](https://github.com/), [AWS S3 buckets & Azure Blog storage containers](https://grayhatwarfare.com/), [Google searches using "Dorks"](https:/www.exploit-db.com/google-hacking-database) |
| `Breach Data Sources` | [HaveIBeenPwned](https://haveibeenpwned.com/) to determine if any corporate email accounts appear in public breach data, [Dehashed](https://www.dehashed.com/) to search for corporate emails with cleartext passwords or hashes we can try to crack offline. We can then try these passwords against any exposed login portals (Citrix, RDS, OWA, 0365, VPN, VMware Horizon, custom applications, etc.) that may use AD authentication. |

### Address Spaces

Some organizations host their own websites and networking infrastructure. Others rely on paid services for infrastructure like GCC, Azure, AWS, etc…

Finding out where the infrastructure resides is important for testing, since we don’t want to interact with infrastructure that is out of scope.

### DNS

- Great way to validate scope and find out the other reachable hosts that the client hasn’t disclosed.
- [whois.domaintools.com](http://whois.domaintools.com) and [viewdns.info](http://viewdns.info)  can help.
- A great way to validate some of the data found from our IP/ASN searches. Not all information about the domain found will be current, and running checks that can validate what we see is always good practice.

### Public Data

Social media reveals organizational structure, equipment, and software details. Job sites like LinkedIn, [Indeed.com](http://Indeed.com), and Glassdoor provide valuable insights through job postings. A `SharePoint Administrator` posting, for instance, indicates a mature SharePoint environment with multiple versions (2013 and 2016), suggesting possible legacy vulnerabilities from in-place upgrades.

### Sharepoint Listings

- Public information such as job listings or social media posts can reveal a lot about a company.
- Good places to dig for details such as phone numbers, emails, org charts, etc…
- Check code repos for unintentional leaks too. Use tools like [Trufflehog](https://github.com/trufflesecurity/truffleHog) and [Grayhat Warefare](https://buckets.grayhatwarfare.com/) to help find these.

# Initial Enumeration of the Domain

We are looking for `Passive identification` of any hosts on the network, followed by `active validation` of the results to find out details about each host (services, names, processes running, potential vulns, etc).

## Gameplan

1. **Figure out what kind of setup the client will let us use. Could be a vm with access to the internal network, or they give you an ip you have to vpn into, etc.**
2. Run a blind test first, without domain credentials. We want to see if we can infiltrate the domain from the outside. We will try to look for the following data points at this time:
    
    
    | **Data Point** | **Description** |
    | --- | --- |
    | `AD Users` | We are trying to enumerate valid user accounts we can target for password spraying. |
    | `AD Joined Computers` | Key Computers include Domain Controllers, file servers, SQL servers, web servers, Exchange mail servers, database servers, etc. |
    | `Key Services` | Kerberos, NetBIOS, LDAP, DNS |
    | `Vulnerable Hosts and Services` | Anything that can be a quick win. ( a.k.a an easy host to exploit and gain a foothold) |
3. **Passive Identification**
    1. Capturing network traffic with `wireshark` or `TCPDump` - Particularly useful in black box testing.
    2. If the host has no GUI, we can use `TCPDump, Net-Miner, Netcreds` to listen to the network traffic
    3. Start building a list of targets (ips of hsots)
    4. Save the PCAP file from any of these network traffic monitoring apps to analyse later.
4. Analyse the network traffic using a tool like `responder` . We might find some hosts that even wireshark and tcpdump didn’t get. 
5. **Active Checking**
    1. ICMP ping sweep the subnet with `fping` . Check if targets are alive, and generate a target list
        - `z0mb34r@htb[/htb]$ fping -asgq 172.16.5.0/23`
        - `a` - alive targets, `s` - print stats at the end of the scan, `g` - generate a list from the CIDR network, `q` - don’t show per host results
    2. Create a list of the hosts discovered, and send it to nmap for further enumeration. 
6. **Nmap Scanning**
    1. Enumerate the hosts we found further, and determine which services are running on each.
    2. We are trying to identify important hosts like `domain controllers or web servers` , and other potentially vulnerable hosts.
    3. Run a quick nmap scan with the `-A` flag to cover the well known ports for web servers, domain services, etc…
    4. Be sure to output the files in all the possible formats for easy editing and feeding into other tools using the `-oA` flag.
7. **Identifying Users**
    1. If we aren’t provided with a user to test with, we have to find a way to establish a foothold in the domain with either:
        1. A cleartext password
        2. NTLM hash for a user
        3. A system shell on a domain joined host
        4. A shell in the context of a domain user account
    2. **Ways to get user creds with Kerbrute - internal AD username enumeration**
        - Stealthy option for AD account enumeration
        - `It takes advantage of the fact that Kerberos pre-authentication failures often will not trigger logs or alerts.`
        - Use kerbrute with a username list such as https://github.com/insidetrust/statistically-likely-usernames from insidetrust. Useful for enumerating users when starting from an unauthenticated perspective.
    3. **Identifying Potential Vulnerabilities**
        - **`NT AUTHORITY\SYSTEM` is basically root for windows.** Many 3rd party services run in the context of this account by default.
        - **A `SYSTEM` account on a `domain-joined` host will be able to enumerate Active Directory by impersonating the computer account, which is essentially just another kind of user account.**

# Finding a Foothold for Entry

## Goal

**To get a set of cleartext credentials for a domain user account, granting us a foothold in the domain to repeat the cycle of enumeration from a credentialed standpoint.**

## Tactics, Techniques, Procedures

- A common way to gather credentials for an initial foothold is a Man in the Middle (MITM) attack on `Link-Local Multicast Name Resolution (LLMNR)` and `NetBIOS Name Service (NBT-NS) broadcasts` .
- This might provide some low-priv or admin level password hashes that can be cracked offline, or maybe some cleartext creds.
- Tools to attempt LLMNR/NBT-NS poisoning

| Tool                                                  | Description                                                                                         | 
| ----------------------------------------------------- | --------------------------------------------------------------------------------------------------- | 
| [Responder](https://github.com/lgandx/Responder)      | Responder is a purpose-built tool to poison LLMNR, NBT-NS, and MDNS, with many different functions. | 
| [Inveigh](https://github.com/Kevin-Robertson/Inveigh) | Inveigh is a cross-platform MITM platform that can be used for spoofing and poisoning attacks.      | 
| [Metasploit](https://www.metasploit.com/)          | Metasploit has several built-in scanners and spoofing modules made to deal with poisoning attacks.  |                                                                                               |     |

### LLMNR/NBT-NS Poisoning from a Linux Host

- MS Windows components that serve as alternate methods of host identification that can be used when DNS fails.
- **Based on the DNS format and allows hosts on the same local link to perform name resolution for other hosts.**
- If DNS resolution of a host fails, the machine will ask the other machines on the local network for the correct host address via LLMNR.
- **LLMNR uses UDP/5355, NBT-NS uses UDP/137.**
- `When LLMNR/NBT-NS is used for name resolution **ANY** host on the network can reply`

### Using Responder for Poisoning

- We can spoof an authoritative name resolution source in the broadcast domain by responding to the LLMNR and NBT-NS traffic as if they have an answer for the requesting host.
- The poisoning is done to get the victims to communicate with our system by **pretending that our rogue system knows the location of the requested host.**
- If the requested host requires name resolution or authentication actions, we can capture the NetNTLM hash and subject it to an offline brute force attack in an attempt to retrieve the cleartext password.
- **The captured authentication request can also be relayed to access another host or used against a different protocol (such as LDAP) on the same host.**
- LLMNR/NBNS spoofing combined with a lack of SMB signing can often lead to administrative access on hosts within a domain.
- Responder should be run with sudo. And let it run for a while on a separate tmux window and come back to it for best results.
- `sudo responder -I {eth0} -{flags}`
- Responder creates a log file per host at `/usr/share/responder/logs` and hashes are saved as `(MODULE_NAME)-(HASH_TYPE)-(CLIENT_IP).txt` .

### Cracking the NTLMv2 Hashes with Hashcat

- Find the mode that’s needed based on the structure of the hash, and the type of hash it is. Refer to https://hashcat.net/wiki/doku.php?id=example_hashes

### LLMNR/NBT-NS Poisoning from a Windows Host

- This kind of poisoning is possible using a windows host as well. Instead of responder, we use [`Inveigh`](https://github.com/Kevin-Robertson/Inveigh)
- The tool works the same way is responder but is written in powershell and c#.

### Using Inveigh

**Powershell - Not actively updated**

Get the module imported in.

```powershell
PS C:\htb> Import-Module .\Inveigh.ps1
```

LLMNR and NBNS spoofing on

```powershell
PS C:\htb> Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

**C# Inveigh - InveighZero**

- Have to compile the executable before being able to run the .exe

```powershell
PS C:\htb> .\Inveigh.exe
```

- When it runs, it shows the options enabled/disabled by default:
    - The options with a `[+]` are default and enabled by default and the ones with a `[ ]` before them are disabled
- Hitting the `Esc` key while its running brings us to the interactive console.
    - Type `HELP` to see the options
    - Type `GET NTLMV2UNIQUE` to get the unique hashes for each unique host
    - `GET NTLMV2USERNAMES` shows the unique usernames
    - `perl -p -i -e 's/\R//g;' svc_qualysCapturedHash.txt` is a bit of code to remove stray new line characters, allowing tools like hashcat or john to parse them.
        - `When capturing NTLM hashes (e.g., from tools like Inveigh), the output might contain unwanted line breaks (especially if copied from a Windows system to Linux). Some password-cracking tools (like hashcat or john) expect hashes to be in a single line or a specific format. This Perl command ensures the file has no stray \r or \n characters, making it easier to parse.`

## Remediation

- MITRE ATT&CK [ID: T1557.001](https://attack.mitre.org/techniques/T1557/001), `Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay`.
- Disabling LLMNR and NBT-NS works, but is a significant change that has to be tested before rollout.
- LLMNR can be disabled in Group Policy:
    - Computer Configuration --> Administrative Templates --> Network --> DNS Client and enabling "Turn OFF Multicast Name Resolution.”
- NBT-NS has to be disabled locally on each host
    - Open `Network and Sharing Center` under `Control Panel`, clicking on `Change adapter settings`, right-clicking on the adapter to view its properties, selecting `Internet Protocol Version 4 (TCP/IPv4)`, and clicking the `Properties` button, then clicking on `Advanced` and selecting the `WINS` tab and finally selecting `Disable NetBIOS over TCP/IP`.
    - We can also create a PowerShell script under Computer Configuration --> Windows Settings --> Script (Startup/Shutdown) --> Startup
        
        ```powershell
        $regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
        Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}
        ```
        
        - In the Local Group Policy Editor, we will need to double click on `Startup`, choose the `PowerShell Scripts` tab, and select "For this GPO, run scripts in the following order" to `Run Windows PowerShell scripts first`, and then click on `Add`
         and choose the script. For these changes to occur, we would have to 
        either reboot the target system or restart the network adapter.
        - To push this out to all hosts in a domain, we could create a GPO using `Group Policy Management` on the Domain Controller and host the script on the SYSVOL share in the scripts folder and then call it via its UNC path such as:`\\inlanefreight.local\SYSVOL\INLANEFREIGHT.LOCAL\scripts`

# Hunting for a User

## Enumerating and Retrieving Password Policies

### IF YOU HAVE CREDENTIALS

- Use a tool like `crackmapexec` or `rpcclient`

```bash
z0mb34r@htb[/htb]$ crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```

### IF YOU DON’T HAVE CREDENTIALS

- We look for avenues like SMB null sessions or LDAP anonymous binds.

### With Linux

### SMB Null Session Enumeration

- If we’re dealing with an earlier version of Windows Server which allows anonymous access to certain SMB shares, then we can use tools such as `enum4linux, enum4linux-ng, crackmapexec, rpcclient, etc` to enumerate the SMB shares.

```bash
# rpcclient
z0mb34r@htb[/htb]$ rpcclient -U "" -N 172.16.5.5
```

- We can also use `rpcclient` to check a domain controller for SMB null session access.

```bash
rpcclient $> querydominfo

Domain:		INLANEFREIGHT
Server:		
Comment:	
Total Users:	3650
Total Groups:	0
Total Aliases:	37
Sequence No:	1
Force Logoff:	-1
Domain Server State:	0x1
Server Role:	ROLE_DOMAIN_PDC
Unknown 3:	0x1
rpcclient $> getdompwinfo
min_password_length: 8
password_properties: 0x00000001
	DOMAIN_PASSWORD_COMPLEX
```

### LDAP Anonymous Bind

- LDAP anonymous binds allow unauthenticated attackers to retrieve information from the domain, such as a complete listing of users, groups, computers, user account attributes, and the domain password policy.
- This is a legacy configuration, and as of Windows Server 2003, only authenticated users are permitted to initiate LDAP requests.
- Tools such as `windapsearch.py, ldapsearch, ad-ldapdomaindump.py, etc` can be used to pull up the password policy.
    - ldapsearch
    
    ```bash
    z0mb34r@htb[/htb]$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
    ```

### With Windows

- Less common, but we can use `net use \\host\ipc$ "" /u:""` to establish a null session from a windows machine

### Enumerating the Password Policy

- If we can authenticate to the domain from a Windows host, we can use built-in Windows binaries such as `net.exe` to retrieve the password policy.

```powershell
C:\htb> net accounts
```

## Making a Target User List

### No Credentials

- If you are on an internal machine but don’t have valid domain credentials, you can look for SMB NULL sessions or LDAP anonymous binds on Domain Controllers. Either of these will allow you to obtain an accurate list of all users within Active Directory and the password policy.
- If you already have credentials for a domain user or SYSTEM access on a Windows host, then you can easily query Active Directory for this information.

- **SMB Null Session to Pull User List**
    
    **enum4linux**
    
    ```bash
    z0mb34r@htb[/htb]$ enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
    ```
    
    **rpcclient**
    
    ```bash
    z0mb34r@htb[/htb]$ enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
    ```
    
    **crackmapexec —users flag**
    
    ```bash
    z0mb34r@htb[/htb]$ crackmapexec smb 172.16.5.5 --users
    ```
    
- **Gathering Users with LDAP Anonymous Bind**
    
    **ldapsearch**
    
    ```bash
    z0mb34r@htb[/htb]$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
    ```
    
    **windapsearch**
    
    ```bash
    z0mb34r@htb[/htb]$ ./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
    ```
    
- **Enumerating Users with Kerbrute**
    - Only if we have no access at all from our position. We can try to validate AD accounts with a wordlist, and then try to spray for passwords
    - Using Kerbrute is stealthy when it enumerates valid AD accounts. But when you spray for passwords with it, it will generate failed Pre-Authentication Attempts, which count towards an account’s failed login count.
    - Kerbrute generates event ID [4768: A Kerberos authentication ticket (TGT) was requested](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768). `This will only be triggered, and found out if Kerberos event logging is enabled via the Group Policy`
    
    ```bash
    z0mb34r@htb[/htb]$  kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 
    ```

### With Credentials

- **crackmapexec with creds**
    
    ```bash
    z0mb34r@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users
    ```

# Password Spraying

## Internal Password Spraying with Linux

**Rpcclient script**

```bash
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```

**Kerbrute**

```bash
z0mb34r@htb[/htb]$ kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
```

**Crackmapexec and Filter logon failures**

Do a password spraying attack first to see if there are any hits

```bash
z0mb34r@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```

Then validate by using the credentials and crackmapexec together

```bash
z0mb34r@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123
```

**Local Admin Spraying with Crackmapexec**

```bash
z0mb34r@htb[/htb]$ sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```

** This technique is quite noisy, and isn’t a good choice if you want stealth.

** Remediation is possible with the free MS tool Local Administrator Password Solution (LAPS) to have AD manage local admin passwords and enforce a unique password on each host that rotates on a set interval.

## Internal Password Spraying with Windows

- After getting a foothold on a domain joned windows host, the `DomainPasswordSpray` tool is highly effective.
- If we are authenticated to the domain, the tool will automatically generate a user list from Active Directory, query the domain password policy, and exclude user accounts within one attempt of locking out.
- If we aren’t authenticated to the domain, we can also provide the tool with a user list

**MITIGATION**

While no single solution will entirely prevent the attack, a defense-in-depth approach will render password spraying attacks extremely difficult.

| Technique | Description |
| --- | --- |
| `Multi-factor Authentication` | Multi-factor authentication can greatly reduce the risk of password spraying attacks. Many types of multi-factor authentication exist, such as push notifications to a mobile device, a rotating One Time Password (OTP) such as Google Authenticator, RSA key, or text message confirmations. While this may prevent an attacker from gaining access to an account, certain multi-factor implementations still disclose if the username/password combination is valid. It may be possible to reuse this credential against other exposed services or applications. It is important to implement multi-factor solutions with all external portals. |
| `Restricting Access` | It is often possible to log into applications with any domain user account, even if the user does not need to access it as part of their role. In line with the principle of least privilege, access to the application should be restricted to those who require it. |
| `Reducing Impact of Successful Exploitation` | A quick win is to ensure that privileged users have a separate account for any administrative activities. Application-specific permission levels should also be implemented if possible. Network segmentation is also recommended because if an attacker is isolated to a compromised subnet, this may slow down or entirely stop lateral movement and further compromise. |
| `Password Hygiene` | Educating users on selecting difficult to guess passwords such as passphrases can significantly reduce the efficacy of a password spraying attack. Also, using a password filter to restrict common dictionary words, names of months and seasons, and variations on the company's name will make it quite difficult for an attacker to choose a valid password for spraying attempts. |

**DETECTION**

Some indicators of external password spraying attacks include many account lockouts in a short period, server or application logs showing many login attempts with valid or non-existent users, or many requests in a short period to a specific application or URL.

## External Password Spraying

Also a common way that attackers use to attempt to gain a foothold on the internet.

**Common Targets**

- Microsoft 0365
- Outlook Web Exchange
- Exchange Web Access
- Skype for Business
- Lync Server
- Microsoft Remote Desktop Services (RDS) Portals
- Citrix portals using AD authentication
- VDI implementations using AD authentication such as VMware Horizon
- VPN portals (Citrix, SonicWall, OpenVPN, Fortinet, etc. that use AD authentication)
- Custom web applications that use AD authentication

# Enumerating Security Controls

| Command | Description |
| --- | --- |
| `Get-MpComputerStatus` | PowerShell cmd-let used to check the status of `Windows Defender Anti-Virus` from a Windows-based host. |
| `Get-AppLockerPolicy -Effective \| select -ExpandProperty RuleCollections` | PowerShell cmd-let used to view `AppLocker` policies from a Windows-based host. |
| `$ExecutionContext.SessionState.LanguageMode` | PowerShell script used to discover the `PowerShell Language Mode` being used on a Windows-based host. Performed from a Windows-based host. |
| `Find-LAPSDelegatedGroups` | A `LAPSToolkit` function that discovers `LAPS Delegated Groups` from a Windows-based host. |
| `Find-AdmPwdExtendedRights` | A `LAPSTookit` function that checks the rights on each computer with LAPS enabled for any groups with read access and users with `All Extended Rights`. Performed from a Windows-based host. |
| `Get-LAPSComputers` | A `LAPSToolkit` function that searches for computers that have LAPS enabled, discover password expiration and can discover randomized passwords. Performed from a Windows-based host. |

# Credentialed Enumeration

- At a minimum, we will have to have acquired a user's cleartext password, NTLM password hash, or SYSTEM access on a domain-joined host.
- Using that, we can dig deeper.
- We use crackmapexec to do domain user enum, domain group enum, check logged on users, check for shares, and spider through shares.

## Using Powershell’s ActiveDirectory Module

**GetModule**

- The Get-Module cmdlet, which is part of the Microsoft.PowerShell.Core module, will list all available modules, their version, and potential commands for use.
- This is a great way to see if anything like Git or custom administrator scripts are installed.

```bash
PS C:\htb> Get-Module
```

**ActiveDirectory**

- if GetModule doesn’t work, import it in via the ActiveDirectory module, and try to run it again

```bash
PS C:\htb> Import-Module ActiveDirectory
PS C:\htb> Get-Module
```

**Get-ADDomain**

- Enumerate basic info about the domain

```bash
PS C:\htb> Get-ADDomain
```

**Get-ADUser**

- Filters for users with the `ServicePrincipalName` property
- This will get us a listing of accounts that may be susceptible to a Kerberoasting attack

```bash
PS C:\htb> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

**Get-ADTrust**

- To verify domain trust relationships

```bash
PS C:\htb> Get-ADTrust -Filter *
```

**Get-ADGroup**

- To get all the AD Groups

```bash
PS C:\htb> Get-ADGroup -Filter * | select name
```

- To get detailed info about an AD Group

```bash
PS C:\htb> Get-ADGroup -Identity "Backup Operators"
```

**Group Membership**

```bash
PS C:\htb> Get-ADGroupMember -Identity "Backup Operators"
```
