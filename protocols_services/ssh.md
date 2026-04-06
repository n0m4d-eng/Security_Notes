# SSH

### What brings you here
Port 22 is open. SSH is usually the *destination* of credentials found elsewhere. If you have a username, brute force or check for key-based auth. If you already have a shell, SSH is used for port forwarding.

### What did you find?

| Finding | Next action |
|---------|-------------|
| SSH with valid credentials | Log in → [../post_exploitation/index.md](../post_exploitation/index.md) |
| SSH key found on target | `chmod 600 id_rsa; ssh -i id_rsa user@IP` |
| Username enumeration possible | Brute force: `hydra -l user -P rockyou.txt ssh://<IP>` |
| Old OpenSSH version | Check for CVEs in searchsploit |
| Rsync on 873 | See Rsync section below |

### Dead ends
- Strong SSH config with key-only auth and no found keys → focus on other services
- Brute force too slow → check for default/weak creds on other services first

## → Where to go next
- Got SSH access → [../post_exploitation/index.md](../post_exploitation/index.md)
- Found SSH key elsewhere → use it here
- Need to tunnel through SSH → [../cheatsheets/pivoting_and_port_forwarding.md](../cheatsheets/pivoting_and_port_forwarding.md)
- Nothing worked → [../STUCK.md](../STUCK.md)
