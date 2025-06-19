---
date: 
tags:
  - Web
  - Command_Injection
---

```table-of-contents
```

# Command Injection

## Description

Command injection is an attack in which the goal is execution of arbitrary commands on the host operating system via a vulnerable application. Command injection attacks are possible when an application passes unsafe user supplied data (forms, cookies, HTTP headers etc.) to a system shell. In this attack, the attacker-supplied operating system commands are usually executed with the privileges of the vulnerable application. Command injection attacks are possible largely due to insufficient input validation.

This attack differs from [Code Injection](https://owasp.org/www-community/attacks/Code\_Injection), in that code injection allows the attacker to add their own code that is then executed by the application. In Command Injection, the attacker extends the default functionality of the application, which execute system commands, without the necessity of injecting code.

Source: [https://owasp.org/www-community/attacks/Command\_Injection](https://owasp.org/www-community/attacks/Command\_Injection)

## Simple Injection

As shown below the input field takes a value for an IP address in which it will ping. Below the value '127.0.0.1' was entered and the results has been shown below.

![](../../Assets/Pasted%20image%2020250619213939.png)

The semicolon in Linux / Unix is used to run a command directly after another. Command injection can potentially be abused to run the required input then a semicolon can be used to execute a trailing command.

Below the IP was pinged then a semicolon used to execute two commands one after another.

![](../../Assets/Pasted%20image%2020250619213955.png)

## Injeciton Fuzzing

We can also fuzz for injection parameters. Taking the same example as above we capture the injection request in Burpsuite leaving the IP address first then fuzzing the posistion 'F' using a wordlist of commands.

![](../../Assets/Pasted%20image%2020250619214005.png)

The Command Injection fuzzing list: [Command Injection.txt](../../Assets/spaces_-MFlgUPYI8q83vG2IJpI_uploads_git-blob-726869b6bf07e532c53f9fcd8203f354ce656ffd_Command%20Injection.txt)

```bash
a);id
a;id
a);id;
a;id;
a);id|
a;id|
a)|id
a|id
a)|id;
a|id
|/bin/ls -al
a);/usr/bin/id
a;/usr/bin/id
```

After running we can view the results in intruder to see which payloads have been successful.

![](../../Assets/Pasted%20image%2020250619214637.png)
