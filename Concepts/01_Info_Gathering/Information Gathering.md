---
date: 2025-06-08
tags:
  - Concept
  - InformationGathering
---

```table-of-contents
```

# Passive

Passive Information Gathering, also known as [_Open-source Intelligence_](https://osintframework.com/) (OSINT), is the process of collecting openly-available information about a target, generally without any direct interaction with that target, in order to keep our footprint low.

## Resources for Manual OSINT

- Google Dorks
	- [DorkSearch - Speed up your Google Dorking](https://dorksearch.com/)
	- [Google dork cheatsheet](https://gist.github.com/sundowndev/283efaddbcf896ab405488330d1bbc06)
- Netcraft
	- [What's that site running? | Netcraft](https://sitereport.netcraft.com/)
- Open Source code
	- [GitHub - Jieyab89/OSINT-Cheat-sheet: OSINT cheat sheet, list OSINT tools, wiki, dataset, article, book , red team OSINT for hackers and OSINT tips and OSINT branch. This repository will grow every time will research, there is a research, science and technology, tutorial. Please use it wisely.](https://github.com/Jieyab89/OSINT-Cheat-sheet?tab=readme-ov-file)
	- 
- Shodan
- Security headers
	- [Security Headers](https://securityheaders.com/)
	- [SSL Server Test (Powered by Qualys SSL Labs)](https://www.ssllabs.com/ssltest/)

## LLM Powered OSINT

Using LLMs to perform OSINT

```c
### Person of Interest Investigation
- "Generate a list of potential usernames for [Full Name] based on common naming conventions."
- "What are the most likely email formats used by [Company Name] employees?"
- "List social media platforms where [Username] might have an account, and suggest search techniques."
- "Extract and summarize publicly available information about [Person's Name] from LinkedIn, Twitter, and GitHub."

### Company & Domain Reconnaissance
- "Generate a list of subdomains for [example.com] based on common naming patterns."
- "What are some potential email addresses for executives at [Company Name]?"
- "Suggest ways to find exposed documents (PDFs, spreadsheets) related to [Target Organization]."
- "Analyze the WHOIS data for [domain.com] and highlight potential points of contact."

### Social Media & Forum Intelligence
- "Search for recent posts on Reddit discussing [Topic/Keyword] and summarize key findings."
- "Find Twitter users who have mentioned [@Username] in the last 30 days."
- "Extract metadata from this [pastebin/text snippet] and identify potential leads."
- "Generate a list of Facebook groups related to [Cybersecurity/Pentesting]."

### Dark Web & Leak Analysis
- "Check if [email/username] appears in any known data breaches."
- "Summarize recent dark web forum discussions about [Target Company]."
- "Analyze this leaked database snippet and extract useful patterns (emails, passwords, etc.)."

### Geospatial & Image OSINT
- "Extract metadata from this image and suggest possible locations based on EXIF data."
- "Analyze this satellite image and identify potential security weaknesses in [Location]."
- "Find publicly accessible webcams near [City/Address]."

### Threat Intelligence & Vulnerability Research
- "List recent CVEs affecting [Software/Service] and their exploitability."
- "Summarize the latest APT group activities related to [Sector]."
- "Generate a Shodan query to find exposed [IoT devices/databases]."

### Automation & Tool Integration
- "Write a Python script to scrape LinkedIn profiles for employees of [Company]."
- "Generate a regex pattern to extract phone numbers from a text dump."
- "Suggest the best OSINT tools for tracking cryptocurrency transactions."

### Report Generation & Summarization
- "Summarize the key findings from this OSINT investigation into [Target] in a structured report."
- "Convert this raw data into a timeline of events for [Incident]."

### Tips for Better Results
- Be specific (e.g., include timeframes, locations, or exact keywords).
- Ask for structured output (e.g., tables, JSON, bullet points).
- Use step-by-step reasoning (e.g., "First search for X, then analyze Y...").
- Verify LLM outputs (they can hallucinate or provide outdated info).
```

# Active

Direct interaction with the target hosts/services.

- DNS Enum
- Port Scanning/Enumeration
- SMB Enumeration
- SMPT Enumeration
- SNMP Enumeration
[Footprinting](../02_Footprinting_Services/Footprinting.md)

## LLM for Active OSINT

```
Using public data from MegacorpOne's website and any information that can be inferred about its organizational structure, products, or services, generate a comprehensive list of potential subdomain names.
	•	Incorporate common patterns used for subdomains, such as:
	•	Infrastructure-related terms (e.g., "api", "dev", "test", "staging").
	•	Service-specific terms (e.g., "mail", "auth", "cdn", "status").
	•	Departmental or functional terms (e.g., "hr", "sales", "support").
	•	Regional or country-specific terms (e.g., "us", "eu", "asia").
	•	Factor in industry norms and frequently used terms relevant to MegacorpOne's sector.

Finally, compile the generated terms into a structured wordlist of 1000  words, optimized for subdomain brute-forcing against megacorpone.com

Ensure the output is in a clean, lowercase format with no duplicates, no bulletpoints and ready to be copied and pasted.
Make sure the list contains 1000 unique entries.
```
