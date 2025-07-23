---
tags:

- cpts
- cybersecurity
- info gathering
---

# Cheat Sheet

```bash
# Usually the sql server runs on TCP port 3306

# Check mysql conf file
cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#" | sed -r '/^\s*$/d'

# Scan with nmap
sudo nmap {target ip} -sV -sC -p3306 --script mysql*

# login to mysql server
mysql -u {user} -p{password} -h {target ip}

# 
```

# Concepts

- Open source SQL language developed by Oracle

- MySQL works according to the `client-server principle` and consists of a MySQL server and one or more MySQL clients

- Databases are often stored as single files with the extension `.sql`

## MySQL Clients

- MySQL clients can retrieve and edit the data using structured queries to the database engine

- CRUD is done using the SQL database language

- Suitable for managing many different databases where clients can send multiple queries simultaneously

- Can be assessed internally/over the public net

## MySQL Databases

- Ideally suited for web applications because the response speed is essential

- Usually comes combined in the LAMP (Linux OS, Apache server, MySQL, PHP) or LEMP (Linux, NginX, MySQL, PHP)

- Sensitive data such as passwords can be stored in their plain-text form by MySQL; however, they are generally encrypted beforehand by the PHP scripts using secure methods such as [One-Way-Encryption](https://en.citizendium.org/wiki/One-way_encryption).

## Default Configuration

- After installing mysql-server using `sudo apt install mysql-server -y`

- There will be an editable conf file. View it using the following command: `cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#" | sed -r '/^\s*$/d'`

## Dangerous Settings

| **Settings**       | **Description**                                                                                              |
| ------------------ | ------------------------------------------------------------------------------------------------------------ |
| `user`             | Sets which user the MySQL service will run as.                                                               |
| `password`         | Sets the password for the MySQL user.                                                                        |
| `admin_address`    | The IP address on which to listen for TCP/IP connections on the administrative network interface.            |
| `debug`            | This variable indicates the current debugging settings                                                       |
| `sql_warnings`     | This variable controls whether single-row INSERT statements produce an information string if warnings occur. |
| `secure_file_priv` | This variable is used to limit the effect of data import and export operations.                              |

## Footprinting

- Usually runs on TCP port `3306`

- Enumerate with `sudo nmap {target ip} -sV -sC -p3306 --script mysql*`

## Interacting with the MySQL Server

| **Command**                                          | **Description**                                                                                       |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `mysql -u <user> -p<password> -h <IP address>`       | Connect to the MySQL server. There should **not** be a space between the '-p' flag, and the password. |
| `show databases;`                                    | Show all databases.                                                                                   |
| `use <database>;`                                    | Select one of the existing databases.                                                                 |
| `show tables;`                                       | Show all available tables in the selected database.                                                   |
| `show columns from <table>;`                         | Show all columns in the selected database.                                                            |
| `select * from <table>;`                             | Show everything in the desired table.                                                                 |
| `select * from <table> where <column> = "<string>";` | Search for needed `string` in the desired table.                                                      |

# References

[3306 - Pentesting Mysql | HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql)