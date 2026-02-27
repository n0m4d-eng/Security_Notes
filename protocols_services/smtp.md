


# SMTP

# Cheat Sheet

```bash
# Get default config
cat /etc/postfix/main.cf | grep -v "#" | sed -r "/^\s*$/d"

# Telnet - HELO/EHLO
telnet {ip address} {port}

# Open relay configuration
mynetworks = 0.0.0.0/0

# Nmap scan
sudo nmap 10.129.14.128 -sC -sV -p25

# Nmap open relay
sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v

# SMTP user enum
smtp-user-enum -M VRFY -U ./footprinting-wordlist.txt -t 10.129.42.195 -m 60 -w 20
```

# Concepts

- Simple Mail Transfer Protocol (SMTP)

- Between email client and an outgoing mail server or between two SMTP servers

- Uses port `25` by default. Newer servers use TCP port `587`

- Used to receive mail from authenticated users/servers, usually using the `STARTTLS` command to change the plaintext connection to an encrypted one

- Used in conjunction with SSL/TLS

- Essential function is preventing spam using auth mechanisms that allow only authorized users to send e-mails. 

- SMTP client = Mail User Client (MUA)

- | Client (`MUA`) | ➞ | Submission Agent (`MSA`) | ➞ | Open Relay (`MTA`) | ➞ | Mail Delivery Agent (`MDA`) | ➞ | Mailbox (`POP3`/`IMAP`) |
  |:-------------- |:--- | ------------------------ | --- | ------------------ | --- | --------------------------- | --- |:-----------------------:|

- Two inherent disadvantages:
  
  - Does not return usable delivery confirmation.
  
  - Users are not authenticated when connection is established, therefore sender of email is unreliable. 

## Default Config

| **Command**  | **Description**                                                                                  |
| ------------ | ------------------------------------------------------------------------------------------------ |
| `AUTH PLAIN` | AUTH is a service extension used to authenticate the client.                                     |
| `HELO`       | The client logs in with its computer name and thus starts the session.                           |
| `MAIL FROM`  | The client names the email sender.                                                               |
| `RCPT TO`    | The client names the email recipient.                                                            |
| `DATA`       | The client initiates the transmission of the email.                                              |
| `RSET`       | The client aborts the initiated transmission but keeps the connection between client and server. |
| `VRFY`       | The client checks if a mailbox is available for message transfer.                                |
| `EXPN`       | The client also checks if a mailbox is available for messaging with this command.                |
| `NOOP`       | The client requests a response from the server to prevent disconnection due to time-out.         |
| `QUIT`       | The client terminates the session.                                                               |

- To interact with the SMTP server, use the telnet tool to intialize a TCP connection with the SMTP server. 

## Dangerous Settings

- To prevent the sent emails from being filtered by spam filters and not reaching the recipient, the sender can use a relay server that the recipient trusts. It is an SMTP server that is known and verified by all others. As a rule, the sender must authenticate himself to the relay server before using it.
  
  Often, administrators have no overview of which IP ranges they have to allow. This results in a misconfiguration of the SMTP server that we will still often find in external and internal penetration tests. Therefore, they allow <mark>all IP addresses not to cause errors in the email traffic</mark> and thus not to disturb or unintentionally interrupt the communication with potential and current customers.

### Open Relay Configuration

- With this setting, this SMTP server can send fake emails and thus initialize communication between multiple parties. Another attack possibility would be to spoof the email and read it.

## Footprinting

- Default Nmap scripts include smtp-commands, which uses the EHL0 command to list all possible commands that can be executed on the starget SMTP server. 