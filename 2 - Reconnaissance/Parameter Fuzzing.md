# Description

Adding or replacing parameters to API requests to access unauthorized data or functionality.

# Command Syntax

```bash
# Key
ffuf -u https://vulnerable.com/api/items?FUZZ=test -w wordlist.txt
ffuf -u https://vulnerable.com/api/items?FUZZ=test -w wordlist.txt -fs 120
ffuf -X POST -u https://vulnerable.com/api/items?FUZZ=test -w wordlist.txt
ffuf -X POST -u https://vulnerable.com/api/items?FUZZ=test -w wordlist.txt -fs 120

# Value
ffuf -u https://vulenrable.com/api/items?test=FUZZ -w wordlist.xt
ffuf -u https://vulnerable.com/api/items?test=FUZZ -w wordlist.txt -fs 120
ffuf -X POST -u https://vulnerable.com/api/items?test=FUZZ -w wordlist.txt
ffuf -X POST -u https://vulnerable.com/api/items?test=FUZZ -w wordlist.txt -fs 120
```

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

[MOC - Reconnaissance](../0%20-%20MOCs/MOC%20-%20Reconnaissance.md)

# References