---
date: 2025-06-08
tags:
  - ActiveDirectory
  - Enumeration
  - Concept
---


```table-of-contents
```



# What is AD?
Active Directory (AD) is a directory service for Windows enterprise environments that was officially implemented in 2000 with the release of Windows Server 2000 and has been incrementally improved upon with the release of each subsequent server OS since.



# Initial Enumeration

## Key Points to Look Out For
| **Data Point**                  | **Description**                                                                                                                 |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `AD Users`                      | We are trying to enumerate valid user accounts we can target for password spraying.                                             |
| `AD Joined Computers`           | Key Computers include Domain Controllers, file servers, SQL servers, web servers, Exchange mail servers, database servers, etc. |
| `Key Services`                  | Kerberos, NetBIOS, LDAP, DNS                                                                                                    |
| `Vulnerable Hosts and Services` | Anything that can be a quick win. ( a.k.a an easy host to exploit and gain a foothold)                                          |


## Identifying Hosts

### 1. Listen to Network Traffic
- Listen to the network traffic to see how many hosts are on the network, and identify them.
**Tools**

```text
- Wireshark
- tcpdump
- net-creds
- net miner
```


### 2. Nmap Enumeration
- Enumerate the hosts further. 
- Look for what services these hosts are running, and identify the web servers and ==Domain Controller==


## Identify Users
- We will need to find a way to establish a foothold in the domain by either ==obtaining clear text credentials== or an ==NTLM password hash for a user, a SYSTEM shell on a domain-joined host, or a shell in the context of a domain user account.==

#### Kerbrute Internal AD Username Enumeration
- Stealthy option for domain account enumeration.
- It takes advantage of the fact that Kerberos pre-authentication failures often will not trigger logs or alerts.
- Use in conjunction with `jsmith.txt` or `jsmith2.txt` from `insidetrust`


### 4. Identify Potential Vulnerabilities
- Possible exploit opportunities (MS08-067, EternalBlue, Bluekeep)
- Abusing a running service running in the context of `SYSTEM`



# Sniffing out a Foothold
- At this point, we have completed our initial enumeration of the domain. We obtained some basic user and group information, enumerated hosts while looking for critical services and roles like a Domain Controller, and figured out some specifics such as the naming scheme used for the domain.
- The next goal is to get some ==valid credentials for a domain user account==.
