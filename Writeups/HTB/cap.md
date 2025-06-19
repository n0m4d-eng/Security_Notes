# Given

ip: 10.10.10.245

# Steps

1. fuzzing found 3 user ids: 0, 1, 2
2. uid o showed a pcap file
3. un/pw in pcap file for nathan
    - un: nathan
    - pw: Buck3tH4TF0RM3!
4. ssh into nathan's acocunt
5. get linpeas, and transfer it into the machine.
6. linpeas shows python3.8 is able to sey uids, which can help escalate privs to root
7. use python script to set uid to root.
    - python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
8. open a bash terminal as root by typing bash
9. locate the flag

# Flags

1. nathan's flag
    - user.txt
    - 901d9e48d3c0129f0d926af5e6368a01
2. root flag:
    - root.txt
    - 9d83872878be411eca8cde19584f5528