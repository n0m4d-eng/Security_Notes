---
---

# Cheat Sheet

```
# Dig ns query
dig ns inlanefreight.htb @10.129.14.128

# Dig version query / class chaos query
dig CH TXT version.bind {site ip address}

# Dig any query
dig any inlanefreight.htb @10.129.14.128

# Dig axfr zone transfer
dig axfr inlanefreight.htb @10.129.14.128

# Subdomain brute forcing
for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done

# Subdomain brute forcing using dnsenum
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```

# Concepts

- DNS - Domain Name System

- The phone book of the net, resolving domain names into ip addresses.

| **Server Type**                | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DNS Root Server`              | The root servers of the DNS are responsible for the top-level domains (`TLD`). As the last instance, they are only requested if the name server does not respond. Thus, a root server is a central interface between users and content on the Internet, as it links domain and IP address. The [Internet Corporation for Assigned Names and Numbers](https://www.icann.org/) (`ICANN`) coordinates the work of the root name servers. There are `13` such root servers around the globe. |
| `Authoritative Nameserver`     | Authoritative name servers hold authority for a particular zone. They only answer queries from their area of responsibility, and their information is binding. If an authoritative name server cannot answer a client's query, the root name server takes over at that point.                                                                                                                                                                                                            |
| `Non-authoritative Nameserver` | Non-authoritative name servers are not responsible for a particular DNS zone. Instead, they collect information on specific DNS zones themselves, which is done using recursive or iterative DNS querying.                                                                                                                                                                                                                                                                               |
| `Caching DNS Server`           | Caching DNS servers cache information from other name servers for a specified period. The authoritative name server determines the duration of this storage.                                                                                                                                                                                                                                                                                                                             |
| `Forwarding Server`            | Forwarding servers perform only one function: they forward DNS queries to another DNS server.                                                                                                                                                                                                                                                                                                                                                                                            |
| `Resolver`                     | Resolvers are not authoritative DNS servers but perform name resolution locally in the computer or router.                                                                                                                                                                                                                                                                                                                                                                               |

- mainly unencrypted

- ![](https://academy.hackthebox.com/storage/modules/27/tooldev-dns.png)

| **DNS Record** | **Description**                                                                                                                                                                                                                                   |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `A`            | Returns an IPv4 address of the requested domain as a result.                                                                                                                                                                                      |
| `AAAA`         | Returns an IPv6 address of the requested domain.                                                                                                                                                                                                  |
| `MX`           | Returns the responsible mail servers as a result.                                                                                                                                                                                                 |
| `NS`           | Returns the DNS servers (nameservers) of the domain.                                                                                                                                                                                              |
| `TXT`          | This record can contain various information. The all-rounder can be used, e.g., to validate the Google Search Console or validate SSL certificates. In addition, SPF and DMARC entries are set to validate mail traffic and protect it from spam. |
| `CNAME`        | This record serves as an alias for another domain name. If you want the domain www.hackthebox.eu to point to the same IP as hackthebox.eu, you would create an A record for hackthebox.eu and a CNAME record for www.hackthebox.eu.               |
| `PTR`          | The PTR record works the other way around (reverse lookup). It converts IP addresses into valid domain names.                                                                                                                                     |
| `SOA`          | Provides information about the corresponding DNS zone and email address of the administrative contact.                                                                                                                                            |

- SOA record is located in domain's zone file. Specifies who is responsible for the operation fo the domain and how the DNS information for the domain is managed.

## Default Config

- The local config files are usually
  
  - named.conf.local
  
  - named.conf.options
  
  - named.conf.log

## Local DNS Config

- Able to define different zones in this file.

- A zone file is a text file that describes a DNS zone with the BIND file format

- Must have **one** SOA record and **at least one** NS record

## Zone Files

- For the IP address to be resolved from the `Fully Qualified Domain Name` (`FQDN`), the DNS server must have a reverse lookup file

- The FQDN is assigned to the last octet of an IP address that corresponds to the respective host using a PTR record

## Dangerous Settings

| **Option**        | **Description**                                                                |
| ----------------- | ------------------------------------------------------------------------------ |
| `allow-query`     | Defines which hosts are allowed to send requests to the DNS server.            |
| `allow-recursion` | Defines which hosts are allowed to send recursive requests to the DNS server.  |
| `allow-transfer`  | Defines which hosts are allowed to receive zone transfers from the DNS server. |
| `zone-statistics` | Collects statistical data of zones.                                            |

## Footprinting

- You can query a DNS server for the other known name servers.

- Done using the NS record and specifying the DNS server we want using the `@` symbol.

- You can also query a DNS server's version using the CHAOS query and type TXT. But this entry must exist in the DNS server.

- Zone transfer means transferring DNS zones to another server.

- Zone transfers happen over port  `53`

- This procedure is called AXFR (Async Full Transfer Zone)

- Zone files are kept identical over several name servers, and zone transfers are how these files are synced up.

- Secret key `rndc-key` is what the servers make use of to connumicate with their own master/slave.

- Original data of a zone is stored on a DNS server and this is called the primary name server. 

- Additional servers are called secondary name servers for this zone. 

- You only CRUD the DNS entries on the primary.

- The individual `A` records with the hostnames can also be found out with the help of a brute-force attack. To do this, we need a list of possible hostnames, which we use to send the requests in order. Such lists are provided, for example, by [SecLists](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/subdomains-top1million-5000.txt).

- cpts

- cybersecurity

- info gathering
