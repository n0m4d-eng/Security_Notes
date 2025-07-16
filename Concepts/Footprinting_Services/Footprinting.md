

# Cheat Sheet

| Code                                                                                                                                                                            | Explanation                                                                                             |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json \| jq .`                                                                                                           | cURL-ing for the ssl certificate data from crt.sh                                                       |
| `curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json \| jq . \| grep name \| cut -d":" -f2 \| grep -v "CN=" \| cut -d'"' -f2 \| awk '{gsub(/\\n/,"\n");}1;' \| sort -u` | Same thing but filtered by unique subdomains                                                            |
| `for i in $(cat subdomainlist);do host $i \| grep "has address" \| grep inlanefreight.com \| cut -d" " -f1,4;done`                                                              | generate a list of IP addresses with a minor adjustment to the cut command and run them through Shodan. |
| `for i in $(cat subdomainlist);do host $i \| grep "has address" \| grep inlanefreight.com \| cut -d" " -f4 >> ip-addresses.txt;done`                                            | Take the subdomain list, and get addresses, and put them into a file called ip-addresses.txt            |
| `for i in $(cat ip-addresses.txt);do shodan host $i;done`                                                                                                                       | Shodan each ip address in the file.                                                                     |
| `dig any inlanefreight.com`                                                                                                                                                     | Get all the DNS records for a domain                                                                    |

# Notes

## Principles

- ID the targets in the client's infrastructure, then examine the individual services and protocols.

| #   | Principle                                                          |
| --- | ------------------------------------------------------------------ |
| 1   | More than meets the eye. Consider all points of  view              |
| 2   | Distinguish between what you see and what you don't see            |
| 3   | There's always more ways to get information. Understand the target |

## Methodology of Enumeration

- Complex processes have a standard methodology that helps us keep our bearings and avoid making mistakes.

- There's a static enumeration methodology for external and internal penttesting. 

- 6 layers / metaphorical boundaries we try to pass with the enumeration process.

<img title="" src="https://academy.hackthebox.com/storage/modules/112/enum-method3.png" alt="image" data-align="left" width="795">

| **Layer**                | **Description**                                                                                        | **Information Categories**                                                                               |
| ------------------------ | ------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------- |
| `1. Internet Presence`   | Identification of internet presence and externally accessible infrastructure.                          | Domains, Subdomains, vHosts, ASN, Netblocks, IP Addresses, Cloud Instances, Security Measures, **OSINT** |
| `2. Gateway`             | Identify the possible security measures to protect the company's external and internal infrastructure. | Firewalls, DMZ, IPS/IDS, EDR, Proxies, NAC, Network Segmentation, VPN, Cloudflare                        |
| `3. Accessible Services` | Identify accessible interfaces and services that are hosted externally or internally.                  | Service Type, Functionality, Configuration, Port, Version, Interface                                     |
| `4. Processes`           | Identify the internal processes, sources, and destinations associated with the services.               | PID, Processed Data, Tasks, Source, Destination                                                          |
| `5. Privileges`          | Identification of the internal permissions and privileges to the accessible services.                  | Groups, Users, Permissions, Restrictions, Environment                                                    |
| `6. OS Setup`            | Identification of the internal components and systems setup.                                           | OS Type, Patch Level, Network config, OS Environment, Configuration files, sensitive private files       |

## Domain Information

- Trying to understand the company's functionality, and which tech structures are necessary for services to be offered successfully and efficiently.

- Gather this type of info passively without active scans.
  
  - Use third party services to understand the target better. 
  
  - Read through the main website, note what the target does, and get clues to what tech they are in.

## Online Presence

- First is to get a first impression of the target's presence on the internet.

- Next identify the hosts that are directly accessible from the internet and not hosted by 3rd parties.

- Sources:
  
  - SSL Certificate from the main site.
  
  - Certificate Transparency logs - [crt.sh]()
  
  - Shodan can be used to find devices and systems permanently connected to the internet. 
  
  - DNS records
    
    - `A` records: We recognize the IP addresses that point to a
       specific (sub)domain through the A record. Here we only see one that we
       already know.
    
    - `MX` records: The mail server records show us which mail 
      server is responsible for managing the emails for the company. Since 
      this is handled by google in our case, we should note this and skip it 
      for now.
    
    - `NS` records: These kinds of records show which name 
      servers are used to resolve the FQDN to IP addresses. Most hosting 
      providers use their own name servers, making it easier to identify the 
      hosting provider.
    
    - `TXT` records: this type of record often contains 
      verification keys for different third-party providers and other security
       aspects of DNS, such as [SPF](https://datatracker.ietf.org/doc/html/rfc7208), [DMARC](https://datatracker.ietf.org/doc/html/rfc7489), and [DKIM](https://datatracker.ietf.org/doc/html/rfc6376),
       which are responsible for verifying and confirming the origin of the 
      emails sent.

## Cloud Resources

- This often starts with the `S3 buckets` (AWS), `blobs` (Azure), `cloud storage` (GCP), which can be accessed without authentication if configured incorrectly.

- You can find out if the target has cloud storage using less invasive methods like Google Dorks:
  
  - `inurl:` 
  
  - `intext:`

- Third party providers like [domain.glass](domain.glass), [grayhatwarefare](https://buckets.grayhatwarfare.com/) can tell us about the target's infra.

- Check for leaked files such as RSA keys that get picked up by these provides.

## Staff

- Searching for and identifying employees on social media platforms can 
  also reveal a lot about the teams' infrastructure and makeup.

- Employees can be identified on various business networks such as [LinkedIn](https://www.linkedin.com) or [Xing](https://www.xing.de)

- Job postings from companies can also tell us a lot about their 
  infrastructure and give us clues about what we should be looking for.
