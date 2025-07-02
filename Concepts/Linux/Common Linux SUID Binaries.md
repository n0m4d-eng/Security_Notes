#Concept/Linux

```table-of-contents
```

# Default Linux Binaries

1. **`passwd`** – Allows users to change their passwords (modifies `/etc/shadow`).
2. **`sudo`** – Runs commands with superuser privileges.
3. **`su`** – Switches to another user (often root).
4. **`mount` / `umount`** – Used for mounting/unmounting filesystems (if SUID is set).
5. **`ping`** – Sends ICMP echo requests (requires raw socket access).
6. **`chsh`** – Changes a user’s login shell.
7. **`chfn`** – Changes user finger information.
8. **`gpasswd`** – Manages `/etc/group` entries.
9. **`newgrp`** – Logs into a new group (rarely used).
10. **`pkexec`** – PolicyKit-based privilege escalation.
11. **`crontab`** – Manages user cron jobs (if SUID is set).
12. **`at`** – Schedules commands for later execution.
13. **`ssh-agent`** – Manages SSH keys (sometimes SUID).
14. **`Xorg`** (older versions) – X server (historically had SUID for hardware access).
15. **`traceroute`** (some implementations) – Network diagnostic tool.

# Code

## Find SUID Binaries

```bash
find / -perm -4000 -type f -exec ls -ld {} \\; 2>/dev/null
```

- `perm -4000` → Matches SUID files.
- `2>/dev/null` → Suppresses permission-denied errors.

## Check for Uncommon Binaries

```bash
!/bin/bash

# List of default SUID binaries (common on most Linux systems)
DEFAULT_SUID_BINARIES=(
    "/usr/bin/passwd"
    "/usr/bin/sudo"
    "/usr/bin/su"
    "/usr/bin/mount"
    "/usr/bin/umount"
    "/usr/bin/ping"
    "/usr/bin/chsh"
    "/usr/bin/chfn"
    "/usr/bin/gpasswd"
    "/usr/bin/newgrp"
    "/usr/bin/pkexec"
    "/usr/bin/crontab"
    "/usr/bin/at"
    "/usr/bin/ssh-agent"
    "/usr/bin/Xorg"  # Sometimes SUID in older systems
    "/usr/bin/traceroute"  # Some implementations
)

# Find all SUID binaries on the system
echo -e "\\n[+] Checking for SUID binaries..."
ALL_SUID_BINARIES=$(find / -perm -4000 -type f -exec ls -la {} \\; 2>/dev/null)

echo -e "\\n[+] Default SUID binaries:"
printf '%s\\n' "${DEFAULT_SUID_BINARIES[@]}" | sort

echo -e "\\n[+] All SUID binaries found on the system:"
echo "$ALL_SUID_BINARIES" | awk '{print $9}' | sort

echo -e "\\n[+] Potentially suspicious SUID binaries (not in default list):"
while read -r binary; do
    if ! printf '%s\\n' "${DEFAULT_SUID_BINARIES[@]}" | grep -q "^$binary$"; then
        echo "[!] Non-default SUID binary: $binary"
        ls -la "$binary" 2>/dev/null
    fi
done <<< "$(echo "$ALL_SUID_BINARIES" | awk '{print $9}')"**
```