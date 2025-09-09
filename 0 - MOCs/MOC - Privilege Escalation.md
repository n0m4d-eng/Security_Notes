# Linux Privilege Escalation:

Enumeration: [[Linux PrivEsc Checklist]]

Kernel Exploits: [[Kernel Exploits]] (Research, Compilation)

Sudo Rights: [[Sudo GTFObin]] (Abusing sudo permissions)

SUID/SGID Binaries: [[SUID GTFObin]] (Abusing SUID bits)

Capabilities: [[Linux Capabilities]] (Abusing process capabilities)

Cron Jobs: [[Cron Jobs]] (Writable scripts, path abuse)

PATH Hijacking: [[PATH Hijacking]]

Writable Files: [[Writable /etc/passwd]], [[Writable /etc/shadow]]

NFS Misconfiguration: [[NFS no_root_squash]]

Processes & Services: [[Abusing Services]], [[Process Injection]]

Environment Variables: [[LD_PRELOAD]], [[LD_LIBRARY_PATH]]

# Windows Privilege Escalation:

Enumeration: [[Windows PrivEsc Checklist]]

Kernel Exploits: [[Windows Kernel Exploits]] (Watson, Sherlock)

## Service Abuse:

[[Windows Service Permissions]] (Unquoted Service Paths, Weak Service Permissions)

[[Service Binary Replacement]]

Token Manipulation: [[Potato Family]] (JuicyPotato, PrintSpoofer, RoguePotato)

AlwaysInstallElevated: [[AlwaysInstallElevated]] (MSI exploitation)

Scheduled Tasks: [[Scheduled Tasks]] (Writable tasks, wildcards)

Registry: [[Registry - Autoruns]], [[Registry - Password Hunting]]

Password Hunting: [[SAM & LSA Secrets]], [[Mimikatz]]

Applications: [[Running Processes]], [[DLL Hijacking]]
