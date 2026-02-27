# Master Penetration Testing Workflow (OSCP Focused)

This document serves as a high-level playbook to guide your penetration testing engagements, especially in the context of the OSCP exam. It breaks down the process into logical phases, linking to more detailed notes in other sections of your `grimoire`.

---

## Phase 0: Setup & Preparation

*   **Lab Setup:** Ensure your Kali Linux VM, VPN access, and any other required tools (e.g., Windows VM for AD attacks) are correctly configured.
*   **Tools Check:** Verify essential tools are installed and updated (Nmap, Burp Suite, Metasploit, Impacket, various PowerShell scripts, etc.).
*   **Note-Taking Environment:** Prepare your note-taking application (e.g., CherryTree, Joplin, Obsidian) and ensure it integrates well with screenshots and code snippets.
*   **Reporting Template:** Have your OSCP reporting template ready to capture findings as you go.

---

## Phase 1: Reconnaissance (Passive & Active)

*   **Goal:** Gather as much information about the target environment as possible without directly interacting with the target systems in a way that might be logged. Then, perform light, detectable interaction.
*   **Key Activities:**
    *   **External Footprinting:** Whois, DNS enumeration, Google Dorking.
        *   _Refer to:_ `2 - Reconnaissance/Google Dorks.md`, `7 - Protocols & Services/DNS.md`, `2 - Reconnaissance/Whois Enumeration.md`
    *   **OSINT:** Publicly available information, LinkedIn, Shodan, Censys.
        *   _Refer to:_ `2 - Reconnaissance/LLM Recon.md` (consider expanding for general OSINT)
    *   **Domain Enumeration (AD):** If applicable, identify domain name, users, groups.
        *   _Refer to:_ `8 - Active Directory/Active Directory Enumeration.md`
    *   **Web Application Recon:** Identify technologies, endpoints, hidden directories, subdomains.
        *   _Refer to:_ `2 - Reconnaissance/CMS Enumeration.md`, `2 - Reconnaissance/Directory Busting.md`
        *   _Consider adding:_ Subdomain Enumeration notes (e.g., `subfinder`, `assetfinder`)
*   **Output:** List of IP addresses, domain names, subdomains, open ports (pre-scanning), identified technologies, potential user accounts, interesting documents/files.

---

## Phase 2: Scanning & Enumeration

*   **Goal:** Actively interact with target systems to identify open ports, running services, operating systems, and potential vulnerabilities.
*   **Key Activities:**
    *   **Host Discovery:** `nmap -sn`, `netdiscover`.
    *   **Port Scanning:** `nmap -sC -sV`, `rustscan`, `masscan`.
        *   _Refer to:_ `5 - Tools/Nmap.md`, `5 - Tools/Rustscan.md`
    *   **Service Enumeration (Deep Dive):** For each open port/service, run targeted enumeration tools.
        *   **HTTP/S (Web Servers):** Directory busting (`ffuf`, `gobuster`), vulnerability scanning (`Nikto`, `whatweb`), manual browsing, source code review.
            *   _Refer to:_ `2 - Reconnaissance/Directory Busting.md`
            *   _Consider adding:_ Web app-specific enumeration notes (e.g., `wp-scan`, `joomcan`).
        *   **SMB/Samba:** `nmap` scripts, `enum4linux`, `smbclient`, `crackmapexec`.
            _Refer to:_ `7 - Protocols & Services/SMB.md`
        *   **FTP:** `nmap` scripts, `ftp` client.
            _Refer to:_ `7 - Protocols & Services/FTP.md`
        *   **SSH:** `nmap` scripts, common credential testing.
            _Refer to:_ `7 - Protocols & Services/SSH.md`
        *   **Databases (MSSQL, MySQL, PostgreSQL):** `nmap` scripts, `sqsh`, `mssqlclient.py`, `odat`.
            _Refer to:_ `7 - Protocols & Services/MSSQL.md`, `7 - Protocols & Services/MySQL.md`, `7 - Protocols & Services/Oracle_TNS.md`
        *   **LDAP/Kerberos (AD):** `nmap` scripts, `ldapsearch`, `kerbrute`, `enum4linux`.
            _Refer to:_ `7 - Protocols & Services/LDAP Injection.md` (expand for general LDAP enum), `8 - Active Directory/Active Directory Enumeration.md`
        *   **Other Protocols:** SNMP, SMTP, RDP.
            _Refer to:_ `7 - Protocols & Services/SNMP.md`, `7 - Protocols & Services/SMTP.md`, `7 - Protocols & Services/Linux_Remote_Management.md`, `7 - Protocols & Services/Windows_Remote_management.md`
    *   **Vulnerability Scanning (Light):** `Nessus` (if permitted), `OpenVAS`.
        *   _Refer to:_ `2 - Reconnaissance/Nessus.md`
*   **Output:** Detailed list of services, versions, discovered shares, web application endpoints, potential vulnerabilities.

---

## Phase 3: Initial Access (Exploitation)

*   **Goal:** Gain a foothold (e.g., reverse shell, command execution, user account) on a target system.
*   **Key Activities:**
    *   **Web Application Exploits:**
        *   SQL Injection, XSS, File Inclusion, File Upload, SSRF, SSTI, XXE, Directory Traversal.
        *   _Refer to:_ `3 - Initial Access/Web/SQLi.md`, `3 - Initial Access/Web/XSS (Cross Site Scripting).md`, `3 - Initial Access/Web/File Inclusion (Local,Remote).md`, `3 - Initial Access/Web/File Upload.md`, `3 - Initial Access/Web/SSRF.md`, `3 - Initial Access/Web/SSTI - Server Site Template Injection.md`, `3 - Initial Access/Web/XXE (XML External Entity) Injection.md`, `3 - Initial Access/Web/Directory Traversal.md`
    *   **Service Exploitation:**
        *   Exploiting known vulnerabilities in specific services (e.g., outdated Apache, vulnerable FTP servers, weak credentials on SSH/RDP).
        *   Brute-forcing credentials (SSH, FTP, web logins, databases).
        *   Client-Side Attacks (e.g., spear-phishing with malicious documents, browser exploits - less common in OSCP).
    *   **Credential Attacks:**
        *   Password spraying, default credentials.
        *   _Consider adding:_ Notes for `Hashcat`/`John` for cracking discovered hashes.
*   **Output:** User-level shell, authenticated session, or command execution capabilities.

---

## Phase 4: Privilege Escalation (Local)

*   **Goal:** Elevate privileges from a low-privileged user to a higher-privileged user (e.g., root on Linux, Administrator/SYSTEM on Windows) on the compromised host.
*   **Key Activities:**
    *   **Linux Privilege Escalation:**
        *   Kernel Exploits, SUID/SGID binaries, capabilities, cron jobs, writable /etc/passwd, weak permissions, service misconfigurations, sudo abuses.
        *   _Refer to:_ `4 - Post-Exploitation/Privilege Escalation/Linux/Linux Privilege Escalation.md`, `4 - Post-Exploitation/Privilege Escalation/Linux/Django Cache RCE.md` (specific example)
    *   **Windows Privilege Escalation:**
        *   Kernel Exploits, Service Misconfigurations (unquoted paths, weak permissions), Scheduled Tasks, Registry Hijacking, DLL Hijacking, Weak File Permissions, Stored Credentials, `SeImpersonatePrivilege` (Potato attacks), AlwaysInstallElevated.
        *   _Refer to:_ `4 - Post-Exploitation/Privilege Escalation/Windows/Windows Privilege Escalation.md`
*   **Output:** Root/SYSTEM level access on the target system.

---

## Phase 5: Post-Exploitation, Persistence & Lateral Movement

*   **Goal:** Maintain access, gather more information, and move to other systems within the network.
*   **Key Activities:**
    *   **System Enumeration (Deep Dive):** Users, groups, network connections, installed software, interesting files (`grep -r pass /etc`, `find / -name "*config*"`), internal network topology.
    *   **Credential Dumping:** Extracting credentials from memory (e.g., `Mimikatz` on Windows), registry, or configuration files.
    *   **Persistence:** Establishing backdoors, scheduled tasks, service modifications to regain access.
    *   **Lateral Movement:** Using dumped credentials or exploited services to access other machines.
        *   **Pivoting & Tunneling:** Setting up tunnels (`ssh -L/-R`, `chisel`, `ligolo-ng`, `metasploit`) to access internal network segments from your attack machine.
        *   _Refer to:_ `9 - Cheatsheets/Pivoting and Port Forwarding.md` (needs to be expanded into a methodology)
        *   **Using Tools:** `PsExec`, `WMI`, `SMBExec`, `Evil-WinRM`, `CrackMapExec`, `Impacket` suite.
    *   **Active Directory Exploitation:**
        *   Kerberoasting, AS-REP Roasting, DCSync, Golden/Silver Ticket attacks, GPO abuses, ACL abuses, Trust Exploitation.
        *   _Refer to:_ `8 - Active Directory/Active Directory Enumeration.md` (needs to be expanded for exploitation)
*   **Output:** Access to additional systems, domain administrator privileges, understanding of the internal network.

---

## Phase 6: Reporting & Remediation (OSCP Specific)

*   **Goal:** Document all findings, steps taken, proof, and provide recommendations.
*   **Key Activities:**
    *   **Documentation:** Capture every command, output, and screenshot for *each* vulnerability found, *each* shell obtained, and *each* privilege escalation.
    *   **Proof.txt:** Ensure you capture `proof.txt` and `local.txt` (or similar flags) for every successfully compromised machine.
    *   **Report Writing:** Structure your report clearly with an executive summary, technical details, steps to reproduce, and remediation advice.
    *   _Consider adding:_ A dedicated `Reporting` section.
*   **Output:** A complete, well-structured penetration test report, suitable for submission.

---

## General Checklists & Tools

*   **Web Testing Checklist:** Use for web application assessments.
    *   _Refer to:_ `1 - Checklists/Web Testing Checklist.md`
*   **Tools:**
    *   _Refer to:_ `5 - Tools/Faketime.md`, `5 - Tools/Nmap.md`, `5 - Tools/Rustscan.md` (expand with other critical tools like Burp Suite, `msfvenom`, `netcat`, `socat`).
*   **Cheatsheets:**
    *   File Transfers: _Refer to:_ `9 - Cheatsheets/File Transfers.md`
    *   Shell Upgrading: _Refer to:_ `9 - Cheatsheets/Shell Upgrading.md`
    *   Shells: _Refer to:_ `9 - Cheatsheets/Shells.md`

---
**Next Steps for You:**
1.  **Review this Master Workflow:** Get a feel for the structure.
2.  **Flesh out the Windows PrivEsc notes:** Add detailed commands, examples, and your own understanding to `4 - Post-Exploitation/Privilege Escalation/Windows/Windows Privilege Escalation.md`.
3.  **Start on Active Directory Exploitation:** This is a major area.
4.  **Create Service-Specific Workflows:** For each protocol in `7 - Protocols & Services`, add "Quick Win" sections.
