# What it is

> Faketime is a thin python wrapper around the amazing C library [libfaketime](https://github.com/wolfcw/libfaketime), written by [Wolfgang Hommel](https://github.com/wolfcw) which you can use to lie to UNIX processes about what time and date it is.

```bash
faketime "$(ntpdate -q administrator.htb | cut -d ' ' -f 1,2)"
```

# How it Works

When you want to fool the process into thinking its a particular date/time, you type in the above command before typing in whatever you want to do.

**If you see a clock skew error, try using this**

```shell
┌──(n0m4d㉿kali)-[/mnt/hgfs/vmware_shared/darkzero]
└─$ faketime "$(ntpdate -q dc01.darkzero.htb | cut -d ' ' -f 1,2)" nxc ldap DC01.darkzero.htb -u 'john.w' -p 'RFulUtONCOL!' -k --get-sid
LDAP        DC01.darkzero.htb 389    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:darkzero.htb)
LDAPS       DC01.darkzero.htb 636    DC01             [+] darkzero.htb\john.w 
LDAPS       DC01.darkzero.htb 636    DC01             Domain SID S-1-5-21-1152179935-589108180-1989892463
```