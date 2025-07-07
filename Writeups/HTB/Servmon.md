---
Started: "06-07-25 | 22:12"
Ended: "06-07-25 |"
---

#CTF/HTB/Windows/Easy

# Given

ServMon is an easy Windows machine featuring an HTTP server that hosts an NVMS-1000 (Network Surveillance Management Software) instance. This is found to be vulnerable to LFI, which is used to read a list of passwords on a user&amp;amp;#039;s desktop. Using the credentials, we can SSH to the server as a second user. As this low-privileged user, it&amp;amp;#039;s possible enumerate the system and find the password for `NSClient++` (a system monitoring agent). After creating an SSH tunnel, we can access the NSClient++ web app. The app contains functionality to create scripts that can be executed in the context of `NT AUTHORITY\SYSTEM`. Users have been given permissions to restart the `NSCP` service, and after creating a malicious script, the service is restarted and command execution is achieved as SYSTEM.
## IP

# Steps

# Creds

# Flags

# Proof