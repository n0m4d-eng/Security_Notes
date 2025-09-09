# Description

The process of discovering hidden files and directories on a web server by trying to brute force a links againt the content of a wordlist.

# Command Syntax

## FFUF

```bash
# Basic directory fuzzing
ffuf -w /path/to/wordlist.txt -u http://target/FUZZ

# Filter to show only 200 or 3xx responses
ffuf -w /path/to/wordlist.txt -u http://target/FUZZ -mc 200,300-399

# Output results to a file
ffuf -w /path/to/wordlist.txt -u http://target/FUZZ -o results.txt

# Recursive directory fuzzing
ffuf -w /path/to/wordlist.txt -u http://target/FUZZ -recursion

# Set number of threads
ffuf -w /path/to/wordlist.txt -u http://target/FUZZ -t 50

# Use proxy
ffuf -w /path/to/wordlist.txt -u http://target/FUZZ -x http://127.0.0.1:8080

# Use a delay between requests
ffuf -w /path/to/wordlist.txt -u http://target/FUZZ -p 0.1-0.5

# Set request timeout
ffuf -w /path/to/wordlist.txt -u http://target/FUZZ -timeout 10

# Match response size
ffuf -w /path/to/wordlist.txt -u http://target/FUZZ -fs 4242

# Example usage
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://$IP/FUZZ
ffuf -w /usr/share/wordlists/dirb/big.txt -u http://$IP/FUZZ
```

## DIRB

```bash
# Basic directory scanning
dirb http://target /path/to/wordlist.txt

# Save output to a file
dirb http://target /path/to/wordlist.txt -o results.txt

# Use custom user-agent
dirb http://target /path/to/wordlist.txt -a "Mozilla/5.0"

# Ignore non-existent pages
dirb http://target /path/to/wordlist.txt -N

# Scan SSL (HTTPS)
dirb https://target /path/to/wordlist.txt

# Recursively scan directories
dirb http://target /path/to/wordlist.txt -r

# Exclude specific status codes
dirb http://target /path/to/wordlist.txt -n -X .php,.html,.txt

# Example usage
dirb http://target.com
```

## Feroxbuster

```bash
# Basic directory fuzzing
feroxbuster -u http://target -w /path/to/wordlist.txt -x php,html,txt

# Set number of threads, verbose mode, ignore certificate errors
feroxbuster -u http://$IP -t 30 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -e 

# Filter specific status codes
feroxbuster -u http://$IP -t 30 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -e -C 404 #ignore denied
feroxbuster -u http://$IP -t 30 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -e -C 404,302 #handle redirects
```

## Gobuster

```bash
# Basic directory scanning
gobuster dir -u http://target -w /path/to/wordlist.txt

# Filter to show only 200 responses
gobuster dir -u http://target -w /path/to/wordlist.txt -s 200

# Specify extensions
gobuster dir -u http://target -w /path/to/wordlist.txt -x php,html,txt

# Save output to a file
gobuster dir -u http://target -w /path/to/wordlist.txt -o results.txt

# Set number of threads
gobuster dir -u http://target -w /path/to/wordlist.txt -t 50

# Use proxy
gobuster dir -u http://target -w /path/to/wordlist.txt -p http://127.0.0.1:8080

# Example usage
gobuster dir -u http://10.11.1.71:80/site/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e txt,php,html,htm
gobuster dir -u http://192.168.196.199 -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -x pdf
```

## Dirsearch

```bash
# Basic directory scanning
dirsearch -u http://target -w /path/to/wordlist.txt

# Filter to show only 200 or 3xx responses
dirsearch -u http://target -w /path/to/wordlist.txt -i 200,300-399

# Specify extensions
dirsearch -u http://target -w /path/to/wordlist.txt -e php,html,txt

# Save output to a file
dirsearch -u http://target -w /path/to/wordlist.txt -r -o results.txt

# Set number of threads
dirsearch -u http://target -w /path/to/wordlist.txt -t 50

# Use proxy
dirsearch -u http://target -w /path/to/wordlist.txt -x http://127.0.0.1:8080

# Ignore SSL certificate warnings
dirsearch -u https://target -w /path/to/wordlist.txt -k

# Exclude specific status codes
dirsearch -u http://target -w /path/to/wordlist.txt --exclude-status 404,403

# Example usage
dirsearch -u http://$IP/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt 
dirsearch -u http://$IP/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 300 --recursive --exclude-status=400,404,405,408
```

## WFUZZ

```bash
# Find available directories
wfuzz --hc 404 -c -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt http://<target_ip>/FUZZ

# Find available directories with cookies
wfuzz --hc 404 -c -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -H "cookie: <cookie_name>=<cookie_value>" http://<target_ip>/FUZZ

# Fuzz data parameters
wfuzz --hc 404 -c -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -d "id=FUZZ&catalogue=1" http://<target_ip>

# Subdomain enumeration
wfuzz --hc 404 -c -w /usr/share/amass/wordlists/subdomains-top1mil-110000.txt -H "HOST: FUZZ.<target_domain>" <target_domain>

# Enumerate hidden directories
wfuzz --hc 404 -c -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt http://<target_ip>/.FUZZ

# Skip SSL Certificate validation
wfuzz --hc 404 -c -k -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt http://<target_ip>/FUZZ

# Use threads to speed up process (not advisable to exceed 200)
wfuzz --hc 404 -c -t <number_of_threads> -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt http://<target_ip>/FUZZ
```

# Use Cases

When you have a web server, and want to find any files/directories that aren't immediately evident or are hidden, eg: admin panels, directories that can be listed, etc...

# Related Notes

[MOC - Reconnaissance](../0%20-%20MOCs/MOC%20-%20Reconnaissance.md)

# References

https://www.thehacker.recipes/web/recon/directory-fuzzing
