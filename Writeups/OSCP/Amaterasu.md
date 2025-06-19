In this lab, you will exploit a file upload vulnerability in a custom REST API service to gain initial access as a low-privilege user. You will escalate privileges using Bash Gobbling combined with a vulnerable tar wildcard execution in a scheduled cron job to achieve root access.

Learning Objectives

- Perform port scanning and identify a REST API service using tools like nmap, curl, and dirb.
- Enumerate the REST API endpoints to discover file upload functionality.
- Exploit the file upload to inject an SSH key into a low-privilege user's directory and gain SSH access.
- Identify a vulnerable cron job that executes a tar command and manipulate it using Bash Gobbling to escalate privileges.
- Gain root access to the lab and retrieve the final flag.

# Given

ip: 192.168.110.249

# Steps

1. Nmap scan
2. Since ftp anon login is allowed, can try to get in, but listing times out
3. Ran AutoRecon on this, and found some hidden api endpoints
4. Try to use the POST endpoint to upload files to the server

```bash
└─$ curl -X POST -F "file=@/home/shaco/Desktop/OSCP/machines/amaterasu/payloads/test.txt" -F "filename=/tmp/test.txt"  <http://192.168.110.249:33414/file-upload>
{"message":"File successfully uploaded"}
```

1. Uploads work, and listing works, but can’t view files or execute them.
2. Upload an id_rsa key using curl and then look to get in

# Findings

1. nmap

![image.png](attachment:960a1380-0f5c-49b3-89d3-fb01ddd2af38:image.png)

1. ftp listing times out
2. hidden api endpoint: [`http://192.168.110.249/`](http://192.168.110.249/) | `/info` , `/help`
3. `/info` endpoint gives this info

```powershell
[
"Python File Server REST API v2.5",
"Author: Alfredo Moroder",
"GET /help = List of the commands"
]
```

1. `/help` gives a set of commands

```powershell
[
"GET /info : General Info",
"GET /help : This listing",
"GET /file-list?dir=/tmp : List of the files",
"POST /file-upload : Upload files"
]
```

# Creds

# Flags