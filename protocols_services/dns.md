---
---

# Description

DNS is a domain name system that allows users to connect to websites using domain names instead of IP addresses. DNS, it is a system that resolves a domain name given to a fixed IP address.

## How it Works

- When “secybr.com” is typed in the address bar of the browser, a DNS Query is sent to determine the IP address of the website.
- This request is first asked to our computer’s DNS cache. If it is among the records, the remaining steps are skipped and automatically redirected to “secybr.com”.
- If it doesn’t have a record in our DNS cache, the query is sent to our local DNS server. This is usually the servers of our internet provider and they are called resolvers.
- If no DNS records are found in the resolver, the query is directed to another server called “Root Name Server” to find DNS records.
- Root Name Servers are the servers responsible for the storage of DNS data worldwide and the smooth operation of the system.
- After the DNS record is found by the root Name Server, it returns to our computer and is cached by our computer.

# Command Syntax

```bash
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

# Common Flags / Options

## DNS Records

- `A` - Returns an IPv4 address of the requested domain as a result.
- `AAAA` - Returns an IPv6 address of the requested domain.
- `MX` - Returns the responsible mail servers.
- `NS` - Returns the DNS (nameservers) for the domain.
- `TXT` - This record can contain various information. The all-rounder can be used, e.g., to validate the Google Search Console or validate SSL certificates. In addition, SPF and DMARC entries are set to validate mail traffic and protect it from spam.
- `CNAME` - This record serves as an alias for another domain name. If you want the domain www.hackthebox.eu to point to the same IP as hackthebox.eu, you would create an A record for hackthebox.eu and a CNAME record for www.hackthebox.eu.
- `PTR` - The PTR record works the other way around (reverse lookup). It converts IP addresses into valid domain names.
- `SOA` - Provides information about the corresponding DNS zone and email address of the administrative contact.

# Use Cases

When you want to find out if the target has any other known nameservers.

# Examples

Practical example from a lab machine or HTB.

```sh
example-command -flag target
```

# Related Notes

[MOC - Reconnaissance](../0%20-%20MOCs/MOC%20-%20Reconnaissance.md)

# References

https://secybr.com/posts/dns-pentesting-best-practicies/