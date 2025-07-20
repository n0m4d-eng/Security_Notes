## Given

ip: 10.10.10.95

## Steps

1. nmap
2. tried default creds for apache tomcat server
3. war file has to be uploaded on the manger
4. create a malicious war file on msfvenom and upload it to the tomcat server
5. use netcat to listen for the reverse shell
6. access the war file via the url to get the shell
7. its a windows system, so dig around.

## Findings

1. apache tomcat manager default creds

## Creds

1. tomcat manager default creds
    - tomcat
    - s3cret

## Flags

user.txt

7004dbcef0f854e0fb401875f26ebd00

root.txt

04a8b36e1545a455393d067e772fe90e