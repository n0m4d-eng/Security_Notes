```yaml
tags:

- cpts
- cybersecurity
- info gathering
```

# Cheat Sheet

```shell
# DIG Commands
# Performs a default A record lookup for the domain.
dig domain.com
# Retrieves the IPv4 address (A record) associated with the domain.
dig domain.com A    
# Retrieves the IPv6 address (AAAA record) associated with the domain.
dig domain.com AAAA    
# Finds the mail servers (MX records) responsible for the domain.
dig domain.com MX    
# Identifies the authoritative name servers for the domain.
dig domain.com NS    
# Retrieves any TXT records associated with the domain.
dig domain.com TXT    
# Retrieves the canonical name (CNAME) record for the domain.
dig domain.com CNAME    
# Retrieves the start of authority (SOA) record for the domain.
dig domain.com SOA    
# Specifies a specific name server to query; in this case 1.1.1.1
dig @1.1.1.1 domain.com    
# Shows the full path of DNS resolution.
dig +trace domain.com    
# Performs a reverse lookup on the IP address 192.168.1.1 to find the associated host name. You may need to specify a name server (PTR check).
dig -x 192.168.1.1    
# Provides a short, concise answer to the query.
dig +short domain.com    
# Displays only the answer section of the query output.
dig +noall +answer domain.com    
# Retrieves all available DNS records for the domain (Note: Many DNS servers ignore ANY queries to reduce load and prevent abuse, as per RFC 8482).
dig domain.com ANY    
```

# Concepts

- Domain Information Groper (DIG)

- Queries DNS servers and retreives various DNS records

## Commands

| Command                         | Description                                                                                                                                                                                          |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `dig domain.com`                | Performs a default A record lookup for the domain.                                                                                                                                                   |
| `dig domain.com A`              | Retrieves the IPv4 address (A record) associated with the domain.                                                                                                                                    |
| `dig domain.com AAAA`           | Retrieves the IPv6 address (AAAA record) associated with the domain.                                                                                                                                 |
| `dig domain.com MX`             | Finds the mail servers (MX records) responsible for the domain.                                                                                                                                      |
| `dig domain.com NS`             | Identifies the authoritative name servers for the domain.                                                                                                                                            |
| `dig domain.com TXT`            | Retrieves any TXT records associated with the domain.                                                                                                                                                |
| `dig domain.com CNAME`          | Retrieves the canonical name (CNAME) record for the domain.                                                                                                                                          |
| `dig domain.com SOA`            | Retrieves the start of authority (SOA) record for the domain.                                                                                                                                        |
| `dig @1.1.1.1 domain.com`       | Specifies a specific name server to query; in this case 1.1.1.1                                                                                                                                      |
| `dig +trace domain.com`         | Shows the full path of DNS resolution.                                                                                                                                                               |
| `dig -x 192.168.1.1`            | Performs a reverse lookup on the IP address 192.168.1.1 to find the associated host name. You may need to specify a name server.                                                                     |
| `dig +short domain.com`         | Provides a short, concise answer to the query.                                                                                                                                                       |
| `dig +noall +answer domain.com` | Displays only the answer section of the query output.                                                                                                                                                |
| `dig domain.com ANY`            | Retrieves all available DNS records for the domain (Note: Many DNS servers ignore `ANY` queries to reduce load and prevent abuse, as per [RFC 8482](https://datatracker.ietf.org/doc/html/rfc8482)). |

# References