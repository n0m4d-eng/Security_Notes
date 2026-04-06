# Credential Cracking

### When to use this
You have a hash (from /etc/shadow, Mimikatz, Responder, Kerberoasting, etc.) and need the plaintext. Identify the hash type first, then pick the right hashcat mode.

---

This cheatsheet provides a quick reference for cracking various types of password hashes using John the Ripper and Hashcat.

---

## I. Hashcat

Hashcat is a powerful GPU-accelerated password recovery tool. Its effectiveness heavily relies on your GPU and wordlist/ruleset.

### A. Basic Usage

*   **Syntax:** `hashcat -m <hash_mode> <hash_file> <wordlist_file> [options]`
*   **Common Options:**
    *   `-m <num>`: Specifies the hash type (see "Common Hash Modes" below).
    *   `-a <num>`: Specifies the attack mode:
        *   `0`: Straight (dictionary attack)
        *   `1`: Combinator attack
        *   `3`: Brute-force / Mask attack
        *   `6`: Hybrid Wordlist + Mask
        *   `7`: Hybrid Mask + Wordlist
    *   `--force`: Override warnings (use with caution, e.g., when running on CPU or unsupported hardware).
    *   `--show`: Show cracked passwords.
    *   `--potfile-disable`: Do not write to the potfile.
    *   `-o <file>`: Write cracked passwords to a specified output file.
    *   `--rules-file <file>`: Apply rules to the wordlist (e.g., `rockyou-30000.rule`).
    *   `--session <name>`: Resume/manage sessions.
    *   `--self-test-disable`: Disable self-test (useful for troubleshooting or specific environments).

### B. Common Hash Modes

| Hash Mode (`-m`) | Description                                | Example Hash                                                                            |
| :--------------- | :----------------------------------------- | :-------------------------------------------------------------------------------------- |
| `0`              | MD5                                        | `d41d8cd98f00b204e9800998ecf8427e`                                                      |
| `100`            | SHA1                                       | `a94a8fe5ccb19ba61c4c0873d391e987982fbbd3`                                              |
| `1400`           | SHA256                                     | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`                     |
| `1800`           | SHA512                                     | `cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e` |
| `1000`           | NTLM                                       | `31d6cfe0d16ae931b73c59d7e0c089c0`                                                      |
| `5600`           | NetNTLMv2 (SMBv2/SMBv3 challenge-response) | `$NETNTLMv2$1122334455667788$1122334455667788$e8a34...`                                |
| `13100`          | Kerberos 5 TGS-REP (Kerberoasting)         | `$krb5tgs$100$*user$realm$host/service*...`                                            |
| `18200`          | Kerberos 5 AS-REP (AS-REP Roasting)        | `$krb5asrep$23$user@REALM:hash`                                                        |
| `500`            | Raw MD5, Joomla, WordPress (MD5(pass))     | `d41d8cd98f00b204e9800998ecf8427e`                                                      |
| `11000`          | MS-CHAPv2                                  | `admin:$CHAPv2$::admin:$CHALLENGE$RESPONSE`                                            |

### C. Example Commands

1.  **Cracking NTLM (from `secretsdump.py` or SAM dump):**
    ```bash
    hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt -o cracked_ntlm.txt --force --show
    ```
2.  **Cracking Kerberoast (TGS-REP):**
    ```bash
    hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt -o cracked_kerb.txt --force --show
    ```
3.  **Cracking AS-REP Roasting (AS-REP):**
    ```bash
    hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt -o cracked_asrep.txt --force --show
    ```
4.  **NTLM with Ruleset (e.g., `rockyou-30000.rule` for common modifications):**
    ```bash
    hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt --rules-file /usr/share/hashcat/rules/rockyou-30000.rule -o cracked_ntlm_rules.txt --force --show
    ```
5.  **Brute-Force NTLM (e.g., 8-character alphanumeric):**
    ```bash
    hashcat -m 1000 hashes.txt -a 3 ?a?a?a?a?a?a?a?a --force -o brute_ntlm.txt --show
    ```
    *   `?a`: all lowercase, uppercase, digits, and special characters.
    *   `?l`: lowercase alphabet
    *   `?u`: uppercase alphabet
    *   `?d`: digits
    *   `?s`: special characters
    *   `?h`: half-byte (0-F)

## II. John the Ripper (JtR)

John the Ripper is another powerful and versatile password cracker, often used for CPU-based cracking or when specific formats are better supported.

### A. Basic Usage

*   **Syntax:** `john [options] <hash_file>`
*   **Common Options:**
    *   `--wordlist=<file>`: Specify a wordlist.
    *   `--rules=<rule_name>`: Apply rules (e.g., `wordlist_rules`).
    *   `--format=<format>`: Specify hash format (e.g., `NT`, `krb5tgs`, `netntlmv2`).
    *   `--show`: Show cracked passwords.
    *   `--stdout`: Output candidates to stdout (useful for piping to other tools).
    *   `--incremental=<mode>`: Brute-force attack.
    *   `--session=<name>`: Resume/manage sessions.

### B. Common Hash Formats

JtR often auto-detects formats, but explicit specification can speed things up or resolve ambiguities.

| Format (`--format`) | Description                                | Example Input                                                                           |
| :------------------ | :----------------------------------------- | :-------------------------------------------------------------------------------------- |
| `NT`                | NTLM                                       | `user:::31d6cfe0d16ae931b73c59d7e0c089c0:::comment`                                     |
| `netntlmv2`         | NetNTLMv2                                  | `user::domain:challenge:response:0101000000000000...`                                   |
| `krb5tgs`           | Kerberos 5 TGS-REP (Kerberoasting)         | `$krb5tgs$23$*user$REALM$host/service*user@REALM:$HEX_CIPHER_TEXT`                      |
| `krb5asrep`         | Kerberos 5 AS-REP (AS-REP Roasting)        | `$krb5asrep$23$user@REALM:$HEX_CIPHER_TEXT`                                             |
| `wpapsk`            | WPA-PSK (Wi-Fi)                            | `ssid:mac:client_mac:ESSID:pmk:eapol`                                                   |
| `rar`               | RAR archive                                | `$rar5$`                                                                                |
| `zip`               | ZIP archive                                | `$zip$*`                                                                                |

### C. Example Commands

1.  **Cracking NTLM (from `secretsdump.py` output):**
    ```bash
    john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT ntlm_hashes.txt --show
    ```
2.  **Cracking Kerberoast hashes:**
    ```bash
    john --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5tgs kerberoast_hashes.txt --show
    ```
3.  **Cracking AS-REP hashes:**
    ```bash
    john --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5asrep asrep_hashes.txt --show
    ```
4.  **Cracking `passwd` file (Linux hashes):**
    ```bash
    john --wordlist=/usr/share/wordlists/rockyou.txt passwd_file.txt --show
    ```
5.  **Using rules with John:**
    ```bash
    john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 --format=NT ntlm_hashes.txt --show
    ```

---

## III. Extracting Hashes

*   **Linux:**
    *   `/etc/passwd` and `/etc/shadow` (requires root).
    *   `unshadow passwd_file shadow_file > combined_hashes.txt` (to combine for John).
*   **Windows:**
    *   **SAM Database:** Requires SYSTEM access. Can be extracted via `reg save HKLM\SAM sam.hiv` and `reg save HKLM\SYSTEM system.hiv`, then used with `secretsdump.py` or `pwdump`.
    *   **LSASS:** Running `mimikatz lsadump::secrets` or `procdump.exe -ma lsass.exe lsass.dmp` then `mimikatz "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit` for live process memory.
    *   **NTLMv2:** Captured via LLMNR/NBT-NS poisoning (`Responder.py`) or network sniffers.
    *   **Kerberos:** Kerberoasting/AS-REP Roasting techniques.

Remember to always use the most extensive and relevant wordlists you have, and consider generating custom wordlists based on target information. Always ensure you have permission before cracking passwords.