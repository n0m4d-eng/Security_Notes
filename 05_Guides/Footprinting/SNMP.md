---
tags:

- cpts
- cybersecurity
- info gathering
---

# SNMP

# Cheat Sheet

```
# Commands over UDP port 161
# Traps over UDP port 162

# Get default snmp config
cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s*$/d'

# Footprinting snmp using snmpwalk
snmpwalk -v2c -c {name of the community string} {ip address} | tee snmpwalk.txt

# Brute forcing the community strings using onesixtyone and seclists
onesixtyone -c /opt/useful/SecLists/Discovery/SNMP/snmp.txt {ip address}

# Brute forcing community strings with Braa (1.3.6 thing is standard, just fill in community string and ip)
braa <community string>@<IP>:.1.3.6.*   

# 
```

# Concepts

- Simple Network Management Protocol (SNMP)

- Protocol for managing monitoring network devices

- Can be used to handle configuration tasks and change settings remotely.

- Current version: `SNMPv3`

- Transmits control commands using agents over `UDP port 161`

- Uses **traps** over `UDP port 162`

## MIB

- Management Information Base (MIB)

- Text file in which all queryable SNMP objects of a device are listed in a standardized tree hierarchy

- Contains at least  `1 Object Identifier (OID)`

- MIB files are written in `Abstract Syntax Notation One (ASN.1)` based on ASCII

- They don't contain data but they explain where to find which information and what it looks like

## OID

- Represents a node in the heirarchical namespace.

- A unique sequence of numbers allowing the node's position to be identified in the tree structure

- Registry: [Object Identifiers Registry](https://www.alvestrand.no/objectid/)

## SNMP v1

- SNMP Version 1 (SNMPv1)

- First version, still in use.

- No built-in authentication mechanism.

- Doesn't support encryption.

## SNMP v2

- Existed in different versions. The one that exists today is called `v2c` where "c" means "community"

- The "community string" that provides security is only transmitted in **plain text**, meaning there's not inbuilt encryption

## SNMP v3

- Increased security with features such as authentication using un/pw

- There's also transmission encryption (via a pre-shared key) of data

- More complex, with significantly more config options than v2c

## Community Strings

- Can be seen as passwords used to determine whether the requested information can be viewed or not

- You can intercept and read the community strings over the network

- ***Many organizations are still using SNMPv2***

## Default Configuration

Get default config from your server

```shell-session
cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s*$/d'`
```

## Dangerous Settings

| **Settings**                                     | **Description**                                                                       |
| ------------------------------------------------ | ------------------------------------------------------------------------------------- |
| `rwuser noauth`                                  | Provides access to the full OID tree without authentication.                          |
| `rwcommunity <community string> <IPv4 address>`  | Provides access to the full OID tree regardless of where the requests were sent from. |
| `rwcommunity6 <community string> <IPv6 address>` | Same access as with `rwcommunity` with the difference of using IPv6.                  |

## 

## Footprinting

- Use tools like `snmpwalk, onsixtyone, braa`

- Snmpwalk is used to query the OIDs with their information

- Onesixtyone can be used to brute-force the names of the community strings since they can be named arbitrarily by the administrator.