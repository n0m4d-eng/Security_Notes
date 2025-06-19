---
date: 2025-06-08
tags:
  - Tool
  - vulnerability_assessment
---

# Nessus

```table-of-contents
```

### What is Nessus?

Nessus is a widely-used vulnerability scanner developed by Tenable, designed to identify security weaknesses, misconfigurations, and compliance violations across networks, systems, and applications. It employs a plugin-based architecture to perform comprehensive security assessments and is trusted by enterprises for its accuracy and depth of detection.

### Key Capabilities of Nessus

1. **Vulnerability Detection**:
   - Identifies CVEs, zero-days, and unpatched software.
   - Checks for common misconfigurations (open ports, weak protocols).
2. **Compliance Auditing**:
   - Supports frameworks like CIS, NIST, HIPAA, PCI-DSS.
   - Provides pre-built policy templates.
3. **Authenticated Scanning**:
   - Performs deeper inspection using provided credentials (SSH, Windows AD).
4. **High-Speed Scanning**:
   - Distributed scanning for large networks.
5. **Reporting**:
   - Generates detailed reports (PDF, CSV, HTML) with remediation guidance.
6. **Integration**:
   - APIs for SIEMs (Splunk, ELK) and ticketing systems (Jira).

### Installing Nessus

1. Download Nessus package from Tenable's website (Professional or Essentials tier).
2. Install using platform-specific methods:
   - Windows: Run `.msi` installer as admin.
   - Linux: `sudo dpkg -i Nessus-*.deb` (Debian) or `sudo rpm -ivh Nessus-*.rpm` (RHEL).
3. Start the service: `sudo systemctl start nessusd`.
4. Complete setup via `https://localhost:8834`.
5. Activate with a license key and create an admin account.

### Nessus Components

- **Scanner**: Core engine executing vulnerability checks.
- **Web Interface**: Browser-based GUI (port 8834) for scan management.
- **Plugins**: Modular checks (updated daily; e.g., CVE-2024-1234 detection).
- **Policies**: Templates like "Basic Network Scan" or "Credentialed Patch Audit."
- **Scans**: Configurable jobs (targets, schedules, thresholds).
- **Reports**: Exportable results with risk prioritization.

### Performing a Vulnerability Scan

1. Create a new scan (`Scans` > `New Scan`).
2. Select a policy (e.g., "Basic Network Scan").
3. Configure:
   - Targets (IP ranges, hostnames).
   - Exclusions (sensitive systems).
4. Set options:
   - Port scan depth (quick/full).
   - Performance throttling (to avoid overload).
5. Launch (`Save` > `Launch`).

### Analyzing the Results

1. Review the dashboard:
   - Severity breakdown (Critical/High/Medium/Low).
   - Affected hosts count.
2. Inspect findings:
   - CVE IDs and CVSS scores.
   - Affected services (e.g., Apache 2.4.1 on port 80).
3. Filter:
   - By severity (≥High) or plugin type (e.g., "Windows").
4. Export (`Export` > `PDF` for stakeholders).

### Performing an Authenticated Vulnerability Scan

1. Use "Credentialed Patch Audit" policy.
2. Provide credentials:
   - Windows: Domain admin or local admin.
   - Linux: SSH keys or sudo user.
3. Enable "Safe Checks" to avoid crashes.
4. Benefits:
   - Accurate patch detection (e.g., missing KB501234).
   - Registry/service misconfigurations.

### Working with Nessus Plugins

1. **Types / Templates**:
   - Discovery (e.g., SNMP detection).
   - Vulnerability (e.g., Log4j checks).
   - Compliance (e.g., CIS Level 1 benchmarks).
2. **Management**:
   - Auto-update (default) or manual (`Settings` > `Plugin Rules`).
3. **Customization**:
   - Disable risky plugins (e.g., "Denial of Service" category).
4. **Troubleshooting**:
   - Logs: `/opt/nessus/var/nessus/logs`.
   - Reset: `nessuscli fix --reset`.
