# Description

The Modern Port Scanner. **Find ports quickly (3 seconds at its fastest)**.

# Command Syntax

```bash
# Basic RustScan:
rustscan -a <target-ip> -p 1-65535 

# RustScan + Nmap:
rustscan -a <target-ip> -p 1-65535 -- -Pn

# Specific Port Range: 
rustscan -a <target-ip> -r 1-1000

# Adjust Timeout & Batch Size:
rustscan -a <target-ip> -b 500 -u 5000

# Scan Specific Ports Only: 
rustscan -a <target-ip> -p 22,80,443 

# Save Results to File: 
rustscan -a <target-ip> -- -oN [machine]_rustscan.txt

# UDP Scan: 
rustscan -a <target-ip> -- -sU -p 1-65535

# Vulnerability Detection: 
rustscan -a <target-ip> -p 1-65535 -- -sV --script vuln

# Silent Mode: 
rustscan -a <target-ip> -p 1-65535 -g -q 

# Exclude Certain Ports: 
rustscan -a <target-ip> -p 1-65535 --exclude-ports 80,443

# OS Detection: 
rustscan -a <target-ip> -p 1-65535 -- -O

# TCP and UDP Scan: 
rustscan -a <target-ip> -p 1-65535 -- -sS -sU
```

# Common Flags / Options

-flag: Description of what this flag does

# Use Cases

When you need to run an initial search on a large network. This is faster than Nmap. Though for some reason it sometimes isn't accurate.

# Examples

Practical example from a lab machine or HTB.

```sh
example-command -flag target
```

# Related Notes

[MOC - Reconnaissance](../0%20-%20MOCs/MOC%20-%20Reconnaissance.md)

# References

https://github.com/bee-san/RustScan