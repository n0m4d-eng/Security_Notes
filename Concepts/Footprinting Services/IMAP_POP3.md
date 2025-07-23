# IMAP / POP3

---

tags:

- cpts

- cybersecurity

- info gathering

---

# Cheat Sheet

```bash
# Default ports
POP3 default `ports 110, 995`
IMAP default `ports 143, 993`

# Basic Nmap Scan
sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC

# Read the emails in using cURL (you need to get the un/pw for this)
curl -k 'imaps://{ip address}' --user {username:password} (-v in case you want the verbose version)

# Openssl - TSL encrypted POP3 interaction
openssl s_client -connect {ip address}:pop3s

# Openssl - TSL encrypted POP3 interaction
openssl s_client -connect {ip address}:imaps

# Grab banner using telnet
telnet {ip address} 110/143/

# Grab banner using nmap
sudo nmap {ip address} --script=banner -sV -p{port}
```

# Concepts

- Internet Message Access Protocol (IMAP).

- Post Office Protocol (POP3).

- IMAP allows online email management and supports folder structures.

- Client-server based and allows for sync between local email clients and mailbox on the server. 

- POP3 only provides listing, retreiving and deleting emails on the email server. 

- IMAP is **text based** using ACSII format. Operates on port `143` 

- SSL/TLS is used to encrypt IMAP transmissions.

## Default Config

### IMAP Commands

| **Command**                     | **Description**                                                                                               |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `1 LOGIN username password`     | User's login.                                                                                                 |
| `1 LIST "" *`                   | Lists all directories.                                                                                        |
| `1 CREATE "INBOX"`              | Creates a mailbox with a specified name.                                                                      |
| `1 DELETE "INBOX"`              | Deletes a mailbox.                                                                                            |
| `1 RENAME "ToRead" "Important"` | Renames a mailbox.                                                                                            |
| `1 LSUB "" *`                   | Returns a subset of names from the set of names that the User has declared as being `active` or `subscribed`. |
| `1 SELECT INBOX`                | Selects a mailbox so that messages in the mailbox can be accessed.                                            |
| `1 UNSELECT INBOX`              | Exits the selected mailbox.                                                                                   |
| `1 FETCH <ID> all`              | Retrieves data associated with a message in the mailbox.                                                      |
| `1 FETCH <ID> BODY[]`           | Gets the body of the mail                                                                                     |
| `1 CLOSE`                       | Removes all messages with the `Deleted` flag set.                                                             |
| `1 LOGOUT`                      | Closes the connection with the IMAP server.                                                                   |

### POP3 Commands

| **Command**     | **Description**                                             |
| --------------- | ----------------------------------------------------------- |
| `USER username` | Identifies the user.                                        |
| `PASS password` | Authentication of the user using its password.              |
| `STAT`          | Requests the number of saved emails from the server.        |
| `LIST`          | Requests from the server the number and size of all emails. |
| `RETR id`       | Requests the server to deliver the requested email by ID.   |
| `DELE id`       | Requests the server to delete the requested email by ID.    |
| `CAPA`          | Requests the server to display the server capabilities.     |
| `RSET`          | Requests the server to reset the transmitted information.   |
| `QUIT`          | Closes the connection with the POP3 server.                 |

## Dangerous Settings

| **Setting**               | **Description**                                                                           |
| ------------------------- | ----------------------------------------------------------------------------------------- |
| `auth_debug`              | Enables all authentication debug logging.                                                 |
| `auth_debug_passwords`    | This setting adjusts log verbosity, the submitted passwords, and the scheme gets logged.  |
| `auth_verbose`            | Logs unsuccessful authentication attempts and their reasons.                              |
| `auth_verbose_passwords`  | Passwords used for authentication are logged and can also be truncated.                   |
| `auth_anonymous_username` | This specifies the username to be used when logging in with the ANONYMOUS SASL mechanism. |

## Footprinting

- POP3 default `ports 110, 995`

- IMAP default `ports 143, 993`

- `993 and 995` uses TLS/SSL

- can use cURL to interact with the mail server if you have the un/pw of one of the users
  
  - ```shell-session
    curl -k 'imaps://10.129.14.128' --user user:p4ssw0rd -v
    ```

- Can use `openssl` and `ncat` to interact with the IMAP and POP3 server `over SSL`

- **you can use the interaction services only if you have the username and password for someone**
