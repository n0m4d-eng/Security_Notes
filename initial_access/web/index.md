# Web Initial Access — Triage

### What brings you here
You found an HTTP or HTTPS port. This page tells you what to look for and which sub-page to go to based on what you see.

---

## Checklist — Do These First

```bash
# 1. Fingerprint the service
whatweb http://<IP>
curl -I http://<IP>

# 2. Directory bust — always
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -u http://<IP>/FUZZ -e .php,.txt,.bak,.old,.conf,.zip -o ffuf.txt -of md

# 3. Check for CMS
whatweb http://<IP> | grep -i "wordpress\|joomla\|drupal\|magento"
wpscan --url http://<IP> --no-banner   # if WordPress detected

# 4. Check for virtual hosts
gobuster vhost -u http://<IP> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

# 5. Read SSL cert (HTTPS targets)
openssl s_client -connect <IP>:443 </dev/null 2>/dev/null | openssl x509 -noout -text | grep -E "CN=|DNS:"

# 6. Check robots.txt / sitemap / .git
curl http://<IP>/robots.txt
curl http://<IP>/.git/HEAD
```

---

## What Did You Find?

| What you see | What to try | Go to |
|--------------|-------------|-------|
| Login form / auth page | SQLi, default creds, brute force | [sqli.md](sqli.md) |
| File upload input | Upload webshell, bypass extension check | [File Upload.md](File%20Upload.md) |
| URL parameter (`?page=`, `?file=`, `?id=`) | LFI, directory traversal, SQLi | [file_inclusion.md](file_inclusion.md) / [sqli.md](sqli.md) |
| URL parameter with path (`?file=/etc/`) | LFI / directory traversal | [file_inclusion.md](file_inclusion.md) / [directory_traversal.md](directory_traversal.md) |
| Template rendering (`{{`, `${`, `<%=`) | SSTI | [ssti.md](ssti.md) |
| XML input / SOAP endpoint | XXE | [xxe.md](xxe.md) |
| User-controlled redirect or URL | SSRF | [ssrf.md](ssrf.md) |
| Reflected user input | XSS — useful for credential theft | [xss.md](xss.md) |
| WordPress | `wpscan`, plugin vulns, theme editor shell | [file_inclusion.md](file_inclusion.md) |
| Admin panel with default creds | Try `admin:admin`, `admin:password` | — |
| `/phpmyadmin` | Try default creds → INTO OUTFILE webshell | [../network/database_rce.md](../network/database_rce.md) |
| `.git` exposed | Dump source code | [../../reconnaissance/git_dumps.md](../../reconnaissance/git_dumps.md) |
| Source code comments | Read for credentials, API keys, endpoints | — |

---

## Quick Win Attempts — Run These on Every Web Target

```bash
# Default credentials on any login form
admin:admin
admin:password
admin:<hostname>
root:root
test:test

# SQLi entry point test — paste into every input
'
"
' OR '1'='1
' OR 1=1-- -

# LFI quick test — paste into every ?param=value
../../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
php://filter/convert.base64-encode/resource=index.php
```

---

## Dead Ends

| Situation | What to try next |
|-----------|-----------------|
| Directory bust found nothing | Try a larger wordlist (`directory-list-2.3-big.txt`), try more extensions |
| Login form not injectable | Check for username enumeration (different error messages), try brute force |
| WAF blocking payloads | Try encoding: URL, double URL, Unicode, case variation |
| No visible input | Intercept all requests in Burp, look for hidden POST params and headers |
| CMS but no public exploit | Try default credentials, look for exposed admin panels (`/wp-admin`, `/administrator`) |
| Nothing at all | Check other web ports, check vhosts, check UDP |

When nothing on the web port yields access after thorough enumeration → move to [STUCK.md](../../STUCK.md).

---

## Loot to Collect

- Source code with credentials or API keys
- Config files found via LFI (`wp-config.php`, `.env`, `config.php`)
- Hashes or plaintext passwords from the web app database
- Session tokens / JWTs for other accounts

---

## → Where to go next
- Got a shell → [../../post_exploitation/index.md](../../post_exploitation/index.md)
- Found creds → [../../CRED_TRACKER.md](../../CRED_TRACKER.md) then test for reuse
- Nothing worked → [../../STUCK.md](../../STUCK.md)
