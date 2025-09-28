# Description

An attack on the lack of sanitization in templating frameworks used in webapps.

Sometimes we can include malicious input into the templates, and since there aren't proper checks, we have the chance to make the application leak sensitive information, and maybe even give us RCE.

# Exploiting

## Input Vectors

We start with identifying input vectors (parts of the application we can inject our code into) eg: form input areas that might be created using templates.

*If a webapp is created using a framework eg: Django, we can check for the presence of a templating engine (Jinja2 in the case of Django), and check for SSTI on injectable areas*

## Testing for SSTI

Inject template syntax into the targeted area to see if it responds in any way. Different frameworks have different template syntax. 

Try this polyglot payload that triggers a response to an SSTI vulnerability in most cases:

```sh
# remove the space between the first < and % when using. Its there because the whole polyglot breaks the note
${{< %[%'"}}%\. 
```

[This](https://cheatsheet.hackmanit.de/template-injection-table/)is an interactive template injection table that has the most efficient SSTI testing polyglots along with the expected responses for the most commonly used frameworks.

## Identifying the Engine

Based on the response, we figure out which templating engine is being used. 

[The template injection 101 post](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756)summarizes the syntax and detection methods for most templating engines and how the different engines can use the same syntax.

Also check out the [SSTI page on PayloadsAllTheThings](https://swisskyrepo.github.io/PayloadsAllTheThings/Server%20Side%20Template%20Injection/#inject-template-syntax) for a list of payloads to put into the vulnerable application.

## Escalate

Once we figure out the templating language and engine, we can drop in payloads to escalate things to remote commands.

# Use Cases

When there's a webapp created using a web framework. Check for a templating engine, and test the input fields for SSTI

# Examples

- HackNet (HTB)

# Related Notes

[MOC - Initial Access](../../0%20-%20MOCs/MOC%20-%20Initial%20Access.md)

# References

https://www.thehacker.recipes/web/inputs/ssti#%F0%9F%9B%A0%EF%B8%8F-ssti-server-side-template-injection

https://swisskyrepo.github.io/PayloadsAllTheThings/Server%20Side%20Template%20Injection/#summary

https://cheatsheet.hackmanit.de/template-injection-table/