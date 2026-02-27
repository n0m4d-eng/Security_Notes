# Reporting and Evidence Collection (OSCP Focused)

Effective reporting and meticulous evidence collection are paramount for the OSCP exam and real-world penetration testing. This guide provides a framework to ensure you capture all necessary information and structure your final report professionally.

---

## I. OSCP Report Structure Overview

Your OSCP exam report must adhere to a specific structure. Prepare a template beforehand.

1.  **Executive Summary:**
    *   Brief, non-technical overview for management.
    *   Summarize findings, overall risk, and impact.
    *   Highlight key vulnerabilities and compromised systems.
2.  **Technical Report:**
    *   Detailed, technical explanation of all findings.
    *   Each compromised machine (and proof.txt/local.txt) should have its own section.
    *   Each vulnerability leading to access or privilege escalation should be documented.
3.  **Vulnerability Details (for each finding):**
    *   **Vulnerability Name:** Clear, concise (e.g., "Unquoted Service Path", "SQL Injection").
    *   **Affected System:** IP Address, Hostname, OS.
    *   **Description:** Explain the vulnerability and its potential impact.
    *   **Steps to Reproduce:**
        *   **CRITICAL:** This must be precise, step-by-step, and fully reproducible.
        *   Include all commands, inputs, and observed outputs.
        *   Reference screenshots for visual proof.
    *   **Proof:** State clearly how `proof.txt` (root/system) and `local.txt` (user) were obtained.
    *   **Severity:** Low, Medium, High, Critical.
    *   **Remediation:** Actionable advice to fix the vulnerability.
4.  **Overall Attack Path (Optional but Recommended):**
    *   A high-level diagram or narrative showing how initial access was gained and how you moved through the network to compromise multiple machines.
5.  **Appendices:**
    *   Any additional information, such as tool outputs (e.g., Nmap scans, enum4linux results) that are too verbose for the main body but provide context.

---

## II. Evidence Collection Strategy (Live During Exam)

Capture evidence *as you perform the actions*. This prevents missing crucial steps and ensures accuracy.

### A. Core Evidence Requirements

*   **`proof.txt`:** The contents of the root/system flag.
*   **`local.txt`:** The contents of the user-level flag.
*   **Screenshots:** For *every significant step* (shell, privilege escalation, command output, code execution).
    *   **Initial Shell:** Screenshot of your first shell on a machine (e.g., `whoami`, `id`).
    *   **Local.txt:** Screenshot showing `cat local.txt` or `type local.txt`.
    *   **Privilege Escalation:** Screenshots of the commands used and output showing elevated privileges (e.g., `whoami /priv`, `sudo -l`, `root` prompt).
    *   **Proof.txt:** Screenshot showing `cat proof.txt` or `type proof.txt`.
    *   **Any significant command output:** Commands showing enumeration, file transfer success, exploit output.
*   **Full Command History:** Keep a running log of all commands executed in your terminal (e.g., `script` command, tmux/screen logs).

### B. Screenshot Best Practices

1.  **Full Screen Capture:** Always capture your *entire screen* in a single screenshot. This proves you are working in your exam environment.
2.  **Relevant Output Visible:** Ensure the command you executed and its output (including the success/failure) are clearly visible.
3.  **Timestamp (Optional but good):** Your operating system's clock should be visible in the screenshot to provide a timestamp.
4.  **No Cropping/Editing:** Do NOT crop, edit, or alter screenshots in any way. Submit them as raw as possible.
5.  **Contextual Naming:** Name your screenshots clearly (e.g., `machine_name-initial_shell-whoami.png`, `machine_name-privesc-service_exploit.png`).

### C. Note-Taking Workflow

1.  **Pre-configure a Note-Taking Tool:** Use something like CherryTree, Joplin, Obsidian, or even a simple Markdown editor.
2.  **Per-Machine Sections:** Create a new section/page for each target machine.
3.  **Chronological Order:** Document everything in the order it happens.
4.  **Command & Output:** For every command, paste the command *and* its output.
    ```
    # Command to check services
    root@kali:~# systemctl status apache2
    * apache2.service - The Apache HTTP Server
         Loaded: loaded (/lib/systemd/system/apache2.service; enabled; vendor preset: enabled)
         Active: active (running) since Tue 2024-02-27 10:00:00 EST; 1h ago
    ```
5.  **Observations & Thoughts:** Add your own notes, thought processes, and what you're trying next. This is invaluable for recalling your steps later.
6.  **Screenshot Links:** Embed or link your screenshots directly into your notes.
7.  **Flag Tracking:** Keep a clear section for `local.txt` and `proof.txt` for each machine, noting when and how they were obtained.

---

## III. Pre-Exam Preparation

*   **Template Creation:** Create a detailed report template in your preferred format (e.g., Markdown, LibreOffice Writer, MS Word) with all required sections.
*   **Screenshot Tool Practice:** Ensure you are proficient with your screenshot tool.
*   **Practice Reporting:** After each practice lab machine, write a full mini-report to refine your process.

---
**Remember:** The OSCP is as much a reporting exam as it is a hacking exam. A well-documented, reproducible report is essential for passing.