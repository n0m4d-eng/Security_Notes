# Note Taking

![](https://static.offsec.com/media/lms/content_tags/Course-PEN-200.png)

## 5.1.1. Penetration Testing Deliverables

A penetration test or [red team exercise](https://www.aon.com/cyber-solutions/thinking/penetration-testing-or-red-teaming/) is difficult to script in advance. This is because the tester cannot consistently anticipate exactly what kind of machines or networks the client will want to be tested.

Even though the outcome of our assessment is often unpredictable, it is often recommended to define a detailed _scope_ during the preliminary meetings with the customer. This process is especially very helpful when prioritizing business critical targets within large networks.

While the general execution plan for a penetration test will often follow a particular model, most pentests tend to follow the maxim ["no plan survives first contact with the enemy"](https://quoteinvestigator.com/2021/05/04/no-plan). This means that any specific activities we might expect to perform during the engagement might not actually happen, since the reality of the testing environment is almost certainly different than our initial ideas and hypotheses about it. It's therefore difficult to report on penetration tests using prepopulated forms. This is especially the case when the testing is carried out with little prior discussion with the client, for example, if the client is looking to surprise their defending teams in some manner.

As such, instead of preparing a report in advance, the penetration test is executed, and notes are taken as it proceeds to ensure that there is a detailed record of what was done. This makes sure that:

- the penetration test can be repeated if it becomes necessary to demonstrate that an issue is real.
- the penetration test can be repeated after remediation to confirm that an issue has been fixed.
- if there's a system failure during the period of the penetration test, the client and tester can determine if the testing was the cause of the failure.

During a penetration test, some activities may not be permitted. We have to be very clear about the [_Rules of Engagement_](https://www.microsoft.com/en-us/msrc/pentest-rules-of-engagement) (RoE) under which the testing is done. When conducting red team testing, a person will often be assigned the role of "referee" to ensure that the rules of engagement are observed. There may be constraints placed on testing such as not carrying out denial of service attacks, or not engaging in social engineering. Furthermore, the testing work may be in response to the client's regulatory compliance requirements and may need to follow a specific methodology such as the [OWASP Penetration Testing Execution Standard](https://owasp.org/www-project-web-security-testing-guide/latest/3-The_OWASP_Testing_Framework/1-Penetration_Testing_Methodologies). Any such constraints need to be very clear from the outset.

## 5.1.2. Note Portability

Portability of penetration testing notes means being able to pass those notes on to others. Writing notes that are concise and coherent is an integral part of successful note-taking and enables the notes to be used not only by ourselves but also by others. Additionally, concise notes can be quickly adapted for technical reporting.

The need for portability is particularly emphasized when a penetration tester must leave an engagement because of sickness, illness, or other issues. Having a shared understanding of how notes should be taken is especially important for large penetration testing teams, where individuals need to be able to understand the details of other team members' engagements at will.

## 5.1.3. The General Structure of Penetration Testing Notes

We need to take a structured approach to note-taking that is both concise and precise. There are an uncountable number of ways in which we might organize our notes, and it would be futile to attempt to provide a one-size-fits all set of recommendations. Nevertheless, here are some principles that often useful to consider:

- Rather than taking a few general notes assuming that we'll remember how to perform certain actions next time, we should record exactly what we did.
- This means that every command that we type, every line of code that we modify, and even anywhere we click in the GUI should be recorded so that we can reproduce our actions.
- Even if we've taken a lot of notes, if looking at them later doesn't help us remember exactly what happened during the assessment, then they won't be particularly useful to us.
- The notes need to be structured and sufficiently detailed to remove any ambiguity.
- To write a convincing and substantiated technical report later, we need to provide sufficient technical details within our notes.
- If the notes are not written coherently, it will be difficult for someone else to repeat the test and get the same results.

The structure we recommend here for note-taking is sufficiently abstract to allow for personal preferences. As a general rule, we would like the notes to remind us of what occurred and allow us to replicate the issues we identify. A note-taking structure that starts broad and drills down into each section is an easy and expandable method of taking notes. The top-down approach guides us to start with the broadest activity, and then narrow down our focus and expand the level of detail until we have everything, we need to replicate exactly what happened.

Let's now look at an example of the notes we might take for a web vulnerability we discovered:

- **Application Name**: This is important in a multi-application test, and a good habit to get into. The application names also lend itself to building a natural folder and file structure quite nicely.
- **URL**: This is the exact URL that would be used to locate the vulnerability that we've detected.
- **Request Type**: This represents both the type of request (i.e.: GET, POST, OPTIONS, etc.) that was made, as well as any manual changes we made to it. For example, we might intercept a POST request message and change the username or password before forwarding it on.
- **Issue Detail**: This is the overview of the vulnerability that will be triggered by our actions. For example, we may point to a CVE describing the vulnerability if one exists, and/or explain the impact we observe. We may categorize the impact as denial of service, remote code execution, privilege escalation, and so on.
- **Proof of Concept Payload**: This is a string or code block that will trigger the vulnerability. This is the most important part of the note, as it is what will drive the issue home and allow it to be replicated. It should list all of the necessary preconditions and provide the exact code or commands that would need to be used to trigger the vulnerability again.

Let's get more specific and review an example of testing for a _Cross-Site Scripting_ (XSS) vulnerability. The target we tested has a web page aptly named **XSSBlog.html**. When we navigate to it, we can enter a blog entry.

![](https://static.offsec.com/offsec-courses/LIBRARY/imgs/notetaking/89c0b15a538a12feb35cdbecff45908b-xss1.png)

Figure 1: XSS Testing

When we read back the blog entry, we get the following alert:

![](https://static.offsec.com/offsec-courses/LIBRARY/imgs/notetaking/e113a6b758f58011df96c74634acfe7a-xss2.png)

Figure 2: XSS Testing Issue

While making these requests, we keep a record of our actions, as shown below.

```bash
Testing for Cross-Site Scripting

Testing Target: 192.168.1.52
Application:    XSSBlog
Date Started:   31 March 2022

1.  Navigated to the application
    <http://192.168.1.52/XSSBlog.html>
    Result: Blog page displayed as expected

2.  Entered our standard XSS test data:
    You will rejoice to hear that no disaster has accompanied the
    commencement of an enterprise which you have regarded with such
    evil forebodings.<script>alert("Your computer is infected!");</script>
    I arrived here yesterday, and my first task is to assure my dear
    sister of my welfare and increasing confidence in the success of
    my undertaking.

3.  Clicked Submit to post the blog entry.
    Result: Blog entry appeared to save correctly.

4.  Navigated to read the blog post
    <http://192.168.1.52/XSSRead.php>
    Result: The blog started to display and then the expected alert popped up.

5.  Test indicated the site is vulnerable to XSS.

PoC payload: <script>alert(‘Your computer is infected!')</script>

```

> Listing 1 - Example of a Testing Note.

We now have a simple, fast, and expandable way to take coherent and comprehensive notes that another tester can follow. It's worth repeating that the notes are not themselves the report we will deliver to the client, but they will be invaluable when we attempt to put our report together later.

## 5.1.4. Choosing the Right Note-Taking Tool

There are an enormous number of both free and paid note-taking tools available today. To decide on the right tool for a particular engagement, it is important to understand some requirements. In many cases we want to keep all information local to the computer rather than uploading it anywhere else, so certain tools are precluded from being used. By the same token, if an engagement is source-code heavy then a tool that does not allow for code blocks to be inserted is not going to be appropriate.

While a comprehensive list of desirable properties to keep in mind is nearly impossible to enumerate, some of the more important items to remember are:

- **Screenshots**: If a lot of screenshots are necessary, consider a tool that allows for inline screenshot insertion.
- **Code blocks**: Code blocks need formatting to be properly and quickly understood.
- **Portability**: Something that can be used cross-OS, or easily transferred to another place should be high on the list of priorities.
- **Directory Structure**: In an engagement with multiple domains or applications, keeping a coherent structure is necessary. While manually setting up a structure is allowed, a tool that can do this automatically makes things easier.

Now that we have a good baseline of our requirements, let's consider the use of some note-taking tools.

[_Sublime_](https://www.sublimetext.com/download) is a standard text editor that adds lots of useful features and functionality. One of the most important features it provides is flexible syntax highlighting. Syntax highlighting allows us to place code blocks into a file, and those code blocks will be highlighted according to the programming language's specific syntax rules. However, this often comes with limitations. Highlighting two languages is not possible with one file. In an engagement with a single code type, this is not a problem, but for others, we may prefer to use different options. Additionally, it's not currently possible to inline screenshots at the time of writing.

Another tool we can consider is [_CherryTree_](https://github.com/giuspen/cherrytree). This tool comes as standard in Kali. It contains many of the features that are necessary for note-taking. It uses an SQLite database to store the notes we take, and these can be exported as HTML, PDF, plain text, or as a CherryTree document. CherryTree comes with a lot of built-in formatting, and provides a tree structure to store documents, which it calls "nodes" and "subnodes".

Below is an example of CherryTree being used to store penetration testing notes using a simple tree structure.

![](https://static.offsec.com/offsec-courses/LIBRARY/imgs/notetaking/9fdaf471923933513da2f372a7bcd371-cherrytree.png)

Figure 3: CherryTree

The final tool we'll consider is the [_Obsidian_](https://obsidian.md/) markdown editor, which contains all the features that we need for note-taking. We can install Obsidian as a s[nap application](https://snapcraft.io/) or in its [Flatpak](https://flatpak.org/) application form. It also comes as an [AppImage](https://appimage.org/), meaning that all we need to do is copy it into our system, mark it as executable, and run it.

```bash
kali@kali:~$ wget <https://github.com/obsidianmd/obsidian-releases/releases/download/v0.14.2/Obsidian-0.14.2.AppImage>
....
2022-03-31 15:38:53 (1.28 MB/s) - 'Obsidian-0.14.2.AppImage' saved [113102744/113102744]
kali@kali:~$ chmod +x Obsidian-0.14.2.AppImage
kali@kali:~$ ./Obsidian-0.14.2.AppImage

```

> Listing 2 - Getting and Running Obsidian

When we execute the AppImage, we get a welcome screen, which enables us to open an Obsidian vault or create a new one.

![](https://static.offsec.com/offsec-courses/LIBRARY/imgs/notetaking/11f281591fedf5557b3fbc879b313393-obsidian1.png)

Figure 4: Obsidian Welcome Screen

Obsidian stores information in a _Vault_, which is a folder on our system. We can create both markdown files and folders within the Vault. Obsidian's features include a live preview of markdown text, in-line image placement, code blocks, and a multitude of add-ons such as a community-built CSS extension.

An example of directly entering notes in markdown is shown below:

![](https://static.offsec.com/offsec-courses/LIBRARY/imgs/notetaking/02ac6e9a81c736c20c086438719ad31f-obsidian2.png)

Figure 5: Taking Notes in Obsidian

Then, it can be previewed live by Obsidian.

![](https://static.offsec.com/offsec-courses/LIBRARY/imgs/notetaking/bb8e145610cfd717ccaadbe0ae2444f1-obsidian3.png)

Figure 6: Live Preview of Markdown

An Obsidian vault can be relocated to another computer and opened from the Welcome menu. Markdown files can simply be dropped into the Vault folders, which will automatically be recognized by Obsidian.

The use of markdown means that we can provide syntax and formatting that is easily copied to most report generation tools, and a PDF can be generated straight from Obsidian itself.

Tool selection is a personal and situational preference. Some tools are better in certain scenarios than others, but there isn't a perfect tool. It is recommended to take time and try out the tools we've covered, read the documentation, get familiar with them, and then decide which tool works for you. Some additional tools can be found referenced on [nil0x42's website](https://github.com/nil0x42/awesome-hacker-note-taking).

## 5.1.5. Taking Screenshots

Screenshots are an important part of note-taking and technical reporting. A good screenshot can explain the issue being discussed briefly and in more detail than a textual description. Screenshots are particularly useful to help present a technically complex or detail-heavy section of a report. As the saying goes, a picture is worth 1000 words. Conversely, a bad screenshot can obfuscate and draw attention away from what the issue is.

Screenshots are an important way to communicate the visual impact of a finding, and can be far more effective than mere text. For example, it's more effective to show a screenshot of an alert box popping up from an XSS payload than to describe it in words. However, it's more difficult to use a screenshot to describe exactly what's happening when we use something like a buffer overflow payload. Just like we want to use the right tool to perform certain attacks, so we also want to use the right tool to show certain results (such as text vs images).

We can use screenshots to supplement our note-taking or to include them in our report to illustrate the steps we took, which will help another tester reproduce the issues. However, we need to be conscious of the audience. While a penetration tester may consider an alert window to demonstrate XSS as perfectly self-explanatory, developers unfamiliar with the vulnerability may not understand its true cause or impact. It's good practice to always support a screenshot with text.

Screenshots have a specific goal, which is to convey information that would take several sentences to describe or to make an impact. The screenshot should contain exactly enough information to justify not using text, but there shouldn't be too much information to make the screenshot confusing.

To return to the example given above in the notes section, we have found reflected XSS in the username field of the application login. We will properly explain the effects of XSS in the actual report. However, the impact of XSS is far easier to show rather than explain without a visual reference as a base. We must include evidence of arbitrary JavaScript execution, as well as visual components of the site (i.e. the URL in the browser window). If necessary, secondary, or lead-up steps can be captured as well.

A well-constructed screenshot is easy to parse visually. Readers should be able to intuitively understand the picture and its caption without any questions. If there is a greater need for surrounding context, that can be added in a paragraph above or below the image, but the image itself should be understood.

Once again, using the example of XSS in our login form, we will include the following components in the screenshot, resizing the window if necessary. Ideally, we would include the URL as well as some company-specific branding and logos on the form. This lets them know the exact webpage and ties the vulnerability to their corporate image.

The actual pop-up executed in the proof-of-concept is necessary as well, substituted for any more advanced payload as the proof of concept is slowly taken further. Finally, we want to ensure that it is all legible. A screenshot that needs to be zoomed in to be properly viewed disrupts the reader's flow. A good screenshot is immediately legible, as shown below.

![](https://static.offsec.com/offsec-courses/LIBRARY/imgs/notetaking/084ca8e2153f29b8b50b66252f68234c-image1.png)

Figure 7: Good Screenshot

There are several pitfalls we should avoid when using screenshots. We have already discussed making sure the screenshots are legible. We must also ensure there isn't more than one concept illustrated in each screenshot. A screenshot that contains two pieces of pertinent information does not lend itself to being easily understood at a glance. We must also ensure the impact is framed properly in the screenshot. Having the target of the screenshot off-center at the side obfuscates the intent as well. Finally, the caption for the screenshot shouldn't be overly long.

![](https://static.offsec.com/offsec-courses/LIBRARY/imgs/notetaking/7ad83ef7c5a28c0c2d9bc318dd1b7dc6-image3.png)

Figure 8: Bad Screenshot

The screenshot above covers the important information with an irrelevant piece of information, which prevents the full impact of the screenshot from being understood by the reader.

To recap, a good screenshot has the following characteristics:

- only shows one important concept per single screenshot
- is legible
- contains some visual indication that it applies to the client
- contains the material that is being described
- supports the description of the material
- properly frames the material being described

On the other hand, a bad screenshot is one that:

- is illegible
- is generic rather than client-specific
- contains obfuscated or irrelevant information
- is improperly framed

Under the screenshot, we include a caption. A caption is not meant to provide additional context for the picture. A caption is there to describe the picture in a few words. Any additional context that is necessary can be provided in a separate paragraph. In most cases, eight to ten words is an appropriate maximum for a caption.

## 5.1.6. Tools to Take Screenshots

We can take screenshots using native operating system capabilities. Windows, Linux, and macOS all provide tools to take screenshots. We can also use special-purpose tools.

For Windows, the PrintScreen key allows us to take a copy of the full screen, and _Alt/PrtSc_ takes a screenshot of the currently active window. This can then be pasted into a Paint, Word, or PowerPoint document and manipulated as required. We'll often want to crop the image to remove any unwanted material, and we can do that in these applications.

We can also invoke the Windows [_Snipping Tool_](https://en.wikipedia.org/wiki/Snipping_Tool) by pressing the Windows key together with B+s.

![](https://static.offsec.com/offsec-courses/LIBRARY/imgs/notetaking/eeb807bbbdb74da2aa7c49bb2ec38baf-image5.png)

Figure 9: Snipping Tool

The Snipping tool allows us to highlight and take a screenshot of any area of the screen we choose.

MacOS provides the capability to take a screenshot using the keyboard Shift/Command combination with the numeric keys 3, 4, or 5 key. To select and save the entire screen, we can use F+B+3. To highlight and select a specific area on the screen, we can simply use F+B+4 or F+B+5.

We can take a screenshot in Linux using the PrintScreen key. This will capture and save the entire screen to the user's **Images/ directory**. B+PrintScreen will allow for area highlighting and selection. In Kali Linux, we can also use the _Screenshot_ tool which is installed by default and comes with many options such as choosing the active window, selecting a region, adding a delay before taking the actual screenshot, etc.

[_Flameshot_](https://github.com/flameshot-org/flameshot) is an OS-agnostic, open-source, feature-rich screen-capturing tool. It comes with both a command-line and GUI interface and has integrated drawing tools to add highlights, pixelation, text, and other modifications to the captured image.

### Labs

1. A penetration tester and their client should absolutely agree on what before the engagement starts?
2. What two words that end in "cise" are desirable properties of the general structure of penetration testing notes? Input your answer in the form `A and B`.
3. The format of our notes for a web application test should include the application name, URL, issue detail, and proof of concept payload. What else should we include?
4. How many important concepts should be shown in a single screenshot?

## 5.2. Writing Effective Technical Penetration Testing Reports

In this Learning Unit we'll cover the following Learning Objectives:

- Identify the purpose of a technical report
- Understand how to specifically tailor content
- Construct an Executive Summary
- Account for specific test environment considerations
- Create a technical summary
- Describe technical findings and recommendations
- Recognize when to use appendices, resources, and references

## 5.2.1. Purpose of a Technical Report

As vendors of a penetration testing service, we want to provide our clients with as much value as possible. Reports are the mechanism by which value is delivered and the main artifact that enables the client to take forward action. Our ability to find twenty vulnerabilities in a web application won't make a business impact if we can't provide a presentation of both the vulnerabilities and our recommendations on potential remediation. Without a clear direction forward, the client is not getting full value for their time and money.

To properly prepare a report for the client, we must understand two things:

1. The purpose of the report.
2. How we can deliver the information we've collected in a way that the audience can understand.

When a client pays for a penetration testing engagement, it is often (mis)understood that they are "just" paying for an ethical hacker to legally attack their infrastructure to find and exploit weaknesses. While that may be technically necessary to deliver the required results, it is not the fundamental purpose of the engagement. There are even some cases in which clients would prefer not to have their infrastructure attacked at all!

So, what is the point of a company engaging a penetration tester? The end goal is for the client to be presented with a path forward that outlines and highlights all the flaws that are currently present in their systems within the scope of the engagement, ways to fix those flaws in an immediate sense, and strategic goals that will prevent those vulnerabilities from appearing in the future. This output is often provided in the form of a penetration testing report. As far as the client is concerned, the report is (usually) the only deliverable of the engagement that truly matters.

We might wonder how we ought to report on the parts of our engagement where we haven't found any vulnerabilities. In many cases where we don't find vulnerabilities, we should avoid including too many technical details on what we did in the report. A simple statement that no vulnerabilities have been found is often sufficient. We should ensure that we don't confuse the client with the technical details of our attempts, as this will undermine the value of the issues, we did actually find It's the tester's job to present that information in a way that is easy to understand and act upon. That said, some clients may prefer verbose and deep technical reports even on non-issues, which leads to another consideration: the audience.

The client receiving the report is an expert in their own specific industry. They will often (though not always) be aware of the security concerns of that industry and will expect us to have done our homework to also be aware of them. In practice, this means having a deep understanding of what would cause concern to the client in the event of an attack. In other words, understanding their key business goals and objectives. This is another reason why being clear on the Rules of Engagement is so important, because it gives us a window into the client's core concerns.

All issues discovered while testing should be documented but we will want to highlight any issues we find that would affect these key areas. Examples of client-specific key areas of concern could include [HIPAA](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html), which is a framework that governs medical data in the US, and [PCI](https://www.pcisecuritystandards.org/), which is a framework that governs credit card and payment processing.

Let's consider the following scenario. Assume that Client A is a hospital and Client B is a bank, and we are contracted to perform a test on each of their internal infrastructure. We may come up with similar results for both, and while they may have the same technical severity, we may not necessarily document the findings with the same levels of risk and priority for remediation.

Because Client A is a hospital with medical devices connected to their network, doctors and patients who need action to be taken quickly in response to monitoring alerts are very likely to be worried about network up-time and machine readiness. Medical devices connected to the network are often running on old machines with obsolete versions of embedded software. The need for continuous operations may have resulted in these devices missing upgrades and patches. While reporting, the vulnerabilities we find should be highlighted, and then we might suggest isolating the machines on their own logical subnet given that upgrades or patching cannot be applied promptly.

On the other hand, this exact same scenario on Client B's network could be catastrophic. If a server or device in a bank is missing a patch, that could very well be a foothold into the network. Because systems will need to communicate with other systems on the network, complete segmentation may not be feasible. Therefore, a missing patch is of far greater concern and may need to be reported as a critical issue.

As we begin to record our findings, we'll need to keep in mind the situation under which the vulnerability may be exploited and its potential impact. A clear text HTTP login on the internet is considered extremely unsafe. On an internal network, while still unsafe, it is less concerning given that more steps must be accomplished to properly exploit it. In much the same way, a hospital may not care that their Internet-facing login portal accepts TLS 1.0 ciphers. An eCommerce site is likely to be much more concerned, given the PCI violation that accepting TLS 1.0 creates.

As report writers, we must present useful, accurate, and actionable information to the client without inserting our own biases.

## 5.2.2. Tailor the Content

We must deliver skill-appropriate content for all the readers of our report. It may be read by executives, the heads of security, and by technical members of the security team. This means we want to not only provide a simple overview of the issues for the executives, but we will also want to provide sufficient technical detail for the more technical readers.

We can do this by splitting up content into an appropriate structure of sections and subsections. The number of audiences we have for a particular engagement depends heavily on our relationship with the client, their size, budget, and maturity. For the sake of this Module, we'll consider an engagement for which we have only two target audiences. The first, and arguably the more important, is the management level. This is often the level at which many external engagement contracts are signed and where the value of investing in the testing needs to be highlighted. Depending on the business, this may be C-level functions (CISO, CSO, CFO, etc.), or department heads of IT or security.

However, most executives and upper-level directors will not necessarily have the technical ability to follow a detailed technical explanation. We should provide them with a section that highlights the outcome and impact of the engagement in a way that accurately reports on the vulnerabilities found while not being overloaded with technical details.

The second audience we will consider is made up of the technical staff who have the technical knowledge to understand the report and implement the remediations outlined for the vulnerabilities that have been identified. This audience must be provided with enough technical detail to enable them to understand what is wrong, what the impact of each finding is, and how they can be fixed. In addition, this audience greatly benefits when we can provide advice on how to prevent similar types of issues from occurring in the future.

## 5.2.3. Executive Summary

The first section of the report should be an Executive Summary. This enables senior management to understand the scope and outcomes of the testing at a sufficient level to understand the value of the test, and to approve remediation. We start with the quick bite-sized pieces of information that provide the big picture and follow that up with the full Executive Summary.

The Executive Summary should start with outlining the scope of the engagement. Having a clear scope agreed upon in advance of the testing defines the bounds of what will be covered. We then want to be very clear as to what exactly was tested and whether anything was dropped from the scope. Timing issues, such as insufficient testing time due to finding too many vulnerabilities to adequately report on, should be included to ensure that the scope statement for any subsequent test is appropriate. Including the scope statement in the report protects the penetration tester from any suggestion of not having completed the required testing. It also gives the client a more accurate model of what is practical given the budget and time constraints that were initially set.

Second, we want to include the time frame of the test. This includes the length of time spent on testing, the dates, and potentially the testing hours as well.

Third, we should refer to the Rules of Engagement and reference the referee report if a referee was part of the testing team. If denial of service testing was allowed, or social engineering was encouraged, that should be noted here. If we followed a specific testing methodology, we should also indicate that here.

Finally, we can include supporting infrastructure and accounts. Using the example of a web application, if we were given user accounts by the client, include them here along with the IP addresses that the attacks came from (i.e. our testing machines). We should also note any accounts that we created so the client can confirm they have been removed. The following is an example of this high-level structure:

```bash
Executive Summary:

- Scope: <https://kali.org/login.php>
- Timeframe: Jan 3 - 5, 2022
- OWASP/PCI Testing methodology was used
- Social engineering and DoS testing were not in scope
- No testing accounts were given; testing was black box from an external IP address
- All tests were run from 192.168.1.2

```

> Listing 3 - Pertinent Details

Next, we'll prepare the long-form Executive Summary. This is a written summary of the testing that provides a high-level overview of each step of the engagement and establishes severity, context, and a "worst-case scenario" for the key findings from the testing. It's important not to undersell or oversell the vulnerabilities. We want the client's mental model of their security posture to be accurate. For example, if we've found an SQL injection that enables credit card details to be stolen, then that represents a very different severity than if we've found an authentication bypass on a system hosting public data. We would certainly emphasize the former in the Executive Summary, but we may not highlight the latter in this section.

We should make note of any trends that were observed in the testing to provide strategic advice. The executive doesn't need to be given the full technical details in this section, and technical staff will be able to find them as each vulnerability will be expanded upon in later sections of the report. What we can do, however, is to describe the trends we've identified and validate our concerns with summaries of one or two of the more important related findings.

To highlight trends, we want to group findings with similar vulnerabilities. Many vulnerabilities of the same type generally show a failure in that area. For example, if we find stored and reflected XSS, along with SQL injection and file upload vulnerabilities, then user input is clearly not being properly sanitized across the board. This must be fixed at a systemic level. This section is an appropriate place to inform the client of a systemic failure, and we can recommend the necessary process changes as the remediation. In this example, we may encourage the client to provide proper security training for their developers.

It is useful to mention things that the client has done well. This is especially true because while management may be paying for the engagement, our working relationship is often with the technical security teams. We want to make sure that they are not personally looked down upon. Even those penetration tests that find severe vulnerabilities will likely also identify one or two areas that were hardened. Including those areas will soften the impact on people and make the client more accepting of the report as a whole.

The Executive Summary can generally be broken down as follows:

First, we include a few sentences describing the engagement:

```bash
- "The Client hired OffSec to conduct a penetration test of
their kali.org web application in October of 2025. The test was conducted
from a remote IP between the hours of 9 AM and 5 PM, with no users
provided by the Client."

```

> Listing 4 - Describing the Engagement

Next, we add several sentences that talk about some effective hardening we observed:

```bash
- "The application had many forms of hardening in place. First, OffSec was unable to upload malicious files due to the strong filtering
in place. OffSec was also unable to brute force user accounts
because of the robust lockout policy in place. Finally, the strong
password policy made trivial password attacks unlikely to succeed.
This points to a commendable culture of user account protections."

```

> Listing 5 - Identifying the positives

Notice the language here. We do not say something like "It was _impossible_ to upload malicious files", because we cannot make absolute claims without absolute evidence. We were given a limited time and resource budget to perform our engagement and we ourselves are fallible. We must be careful to make sure our language does not preclude the possibility that _we_ were simply unable to find a flaw that does exist and remains undetected.

Next, we introduce a discussion of the vulnerabilities discovered:

```bash
- "However, there were still areas of concern within the application.
OffSec was able to inject arbitrary JavaScript into the browser of
an unwitting victim that would then be run in the context of that
victim. In conjunction with the username enumeration on the login
field, there seems to be a trend of unsanitized user input compounded
by verbose error messages being returned to the user. This can lead
to some impactful issues, such as password or session stealing. It is
recommended that all input and error messages that are returned to the
user be sanitized and made generic to prevent this class of issue from
cropping up."

```

> Listing 6 - Explaining a vulnerability

Several paragraphs of this type may be required, depending on the number and kind of vulnerabilities we found. Use as many as necessary to illustrate the trends but try not to make up trends where they don't exist.

Finally, the Executive Summary should conclude with an engagement wrap-up:

```bash
"These vulnerabilities and their remediations are described in more
detail below. Should any questions arise, OffSec is happy
to provide further advice and remediation help."

```

> Listing 7 - Concise conclusion

We should mention here that not all penetration testers will offer remediation advice, and not all clients will expect it. That said, we believe that the most effective relationships are those between clients and vendors that do work on that level together.

## 5.2.4. Testing Environment Considerations

The first section of the full report should detail any issues that affected the testing. This is usually a small section. At times, there are mistakes or extenuating circumstances that occur during an engagement. While those directly involved will already be aware of them, we should document them in the report to demonstrate that we've been transparent.

It is our job as penetration testers and consultants to inform the client of all circumstances and limitations that affected the engagement. This is done so that they can improve on the next iteration of testing and get the most value for the money they are paying. It is important to note that not every issue needs to be highlighted, and regardless of the circumstances of the test, we need to ensure the report is professional.

We'll consider three potential states regarding extenuating circumstances:

- **Positive Outcome**: "There were no limitations or extenuating circumstances in the engagement. The time allocated was sufficient to thoroughly test the environment."
- **Neutral Outcome**: "There were no credentials allocated to the tester in the first two days of the test. However, the attack surface was much smaller than anticipated. Therefore, this did not have an impact on the overall test. OffSec recommends that communication of credentials occurs immediately before the engagement begins for future contracts, so that we can provide as much testing as possible within the allotted time."
- **Negative Outcome**: "There was not enough time allocated to this engagement to conduct a thorough review of the application, and the scope became much larger than expected. It is recommended that more time is allocated to future engagements to provide more comprehensive coverage."

The considerations we raise in this section will allow both us and the client to learn from mistakes or successes on this test and apply them to future engagements.

## 5.2.5. Technical Summary

The next section should be a list of all the key findings in the report, written out with a summary and recommendation for a technical person, like a security architect, to learn at a glance what needs to be done.

This section should group findings into common areas. For example, all weak account password issues that have been identified would be grouped, regardless of the testing timeline. An example of the structure of this section might be:

- User and Privilege Management
- Architecture
- Authorization
- Patch Management
- Integrity and Signatures
- Authentication
- Access Control
- Audit, Log Management and Monitoring
- Traffic and Data Encryption
- Security Misconfigurations

An example of a technical summary for Patch Management is as follows:

```bash
4. Patch Management

Windows and Ubuntu operating systems that are not up to date were
identified. These are shown to be vulnerable to publicly-available
exploits and could result in malicious execution of code, theft
of sensitive information, or cause denial of services which may
impact the infrastructure. Using outdated applications increases the
possibility of an intruder gaining unauthorized access by exploiting
known vulnerabilities. Patch management ought to be improved and
updates should be applied in conjunction with change management.

```

> Listing 8 - Example Technical Summary

The section should finish with a risk heat map based on vulnerability severity adjusted as appropriate to the client's context, and as agreed upon with a client security risk representative if possible.

## 5.2.6. Technical Findings and Recommendation

The Technical Findings and Remediation section is where we include the full technical details relating to our penetration test, and what we consider to be the appropriate steps required to address the findings. While this is a technical section, we should not assume the audience is made up of penetration testers.

Not everyone, even those who work within the technologies that were being tested, will fully understand the nuances of the vulnerabilities. While a deep technical dive into the root causes of an exploit is not always necessary, a broad overview of how it was able to take place should usually be provided. It is better to assume less background knowledge on behalf of the audience and give too much information, rather than the opposite.

This section is often presented in tabular form and provides full details of the findings. A finding might cover one vulnerability that has been identified or may cover multiple vulnerabilities of the same type.

It's important to note that there might be a need for an attack narrative. This narrative describes, in story format, exactly what happened during the test. This is typically done for a simulated threat engagement but is also useful at times to describe the more complex exploitation steps required for a regular penetration test. If it is necessary, then writing out the attack path step-by-step, with appropriate screenshots, is generally sufficient. An extended narrative could be placed in an Appendix and referenced from the findings table.

Below are three example entries:

|Ref|Risk|Issue Description and Implications|Recommendations|
|---|---|---|---|
|1|H|Account, Password, and Privilege Management is inadequate. Account management is the process of provisioning new accounts and removing accounts that are no longer required. The following issues were identified by performing an analysis of 122,624 user accounts post-compromise: 722 user accounts were configured to never expire; 23,142 users had never logged in; 6 users were members of the domain administrator group; default initial passwords were in use for 968 accounts.|All accounts should have passwords that are enforced by a strict policy. All accounts with weak passwords should be forced to change them. All accounts should be set to expire automatically. Accounts no longer required should be removed.|
|2|H|Information enumerated through an anonymous SMB session. An anonymous SMB session connection was made, and the information gained was then used to gain unauthorized user access as detailed in Appendix E.9.|To prevent information gathering via anonymous SMB sessions: Access to TCP ports 139 and 445 should be restricted based on roles and requirements. Enumeration of SAM accounts should be disabled using the Local Security Policy > Local Policies > Security Options|
|3|M|Malicious JavaScript code can be run to silently carry out malicious activity. A form of this is reflected cross-site scripting (XSS), which occurs when a web application accepts user input with embedded active code and then outputs it into a webpage that is subsequently displayed to a user. This will cause attacker-injected code to be executed on the user's web browser. XSS attacks can be used to achieve outcomes such as unauthorized access and credential theft, which can in some cases result in reputational and financial damage as a result of bad publicity or fines. As shown in Appendix E.8, the \[client\] application is vulnerable to an XSS vulnerability because the username value is displayed on the screen login attempt fails. A proof-of-concept using a maliciously crafted username is provided in Appendix E.|Treat all user input as potentially tainted and perform proper sanitization through special character filtering. Adequately encode all user-controlled output when rendering to a page. Do not include the username in the error message of the application login.|

> Table 1 - Findings and Recommendations

It's important to understand that what we identify as the severity of an issue based on its vulnerability score is not context-specific business risk. It only represents technical severity, even if we adjust it based on likelihood. We can reflect this in our findings as technical severity, or we can work with the client's risk team to gain an understanding of the appropriate level of business risk by including consideration of the unique business impact to the client.

We can start our findings description with a sentence or two describing what the vulnerability is, why it is dangerous, and what an attacker can accomplish with it. This can be written in such a way to provide insight into the immediate impact of an attack. We then describe some of the technical details about the vulnerability. There is often no need to go into overwhelming detail; simply explain at a basic level what the vulnerability is and how to exploit it. The intention is to describe a complex exploit in a way that most technical audiences can understand.

We also need to include evidence to prove the vulnerability identified is exploitable, along with any further relevant information. If this is simple, it can be included inline as per the first entry above. Otherwise, it can be documented in an appendix as shown in the second entry.

Once the details of the vulnerability have been explained, we can describe the specific finding that we have identified in the system or application. We will use the notes that we took during testing and the screenshots that support them to provide a detailed account. Although this is more than a few sentences, we'll want to summarize it in the table and reference an appendix for the full description.

It's good practice to use our notes and screenshots to walk the reader through how we achieved the result step-by-step. The screenshots should contain a short explanation of what it shows. We should not rely on the screenshot to speak for itself. We should present the impact of the vulnerability in a way that frames its severity for the client in an appropriate manner and is directly relevant to the business or application.

The remediation advice should be detailed enough to enable system and application administrators to implement it without ambiguity. The remediation should be clear, concise, and thorough. It should be sufficient to remove the vulnerability in a manner acceptable to the client and relevant to the application. Presenting remediation that is excessive, unacceptably costly, or culturally inappropriate (e.g. not allowing remote logins for a remote working environment) will lead to the fix never being implemented. A strong understanding of the needs of the client is necessary here.

There are several other important items to keep in mind. First, broad solutions should be avoided, in favor of things that drill down into the specifics of the application and the business. Second, theoretical solutions are not effective in combating a vulnerability. Make sure that any solution given has a concrete and practical implementation. Finally, do not layer multiple steps into one proposed solution. Each distinct step should be its own solution.

The Technical Findings and Recommendations section will likely be a major part of the report and the time and effort invested in writing it should reflect its importance.

In describing the findings, we will present the means of replicating them, either in the body of the report or in an appendix. We need to show exactly where the application was affected, and how to trigger the vulnerability. A full set of steps to replicate the finding should be documented with screenshots. This includes steps that we take for granted (such as running with administrative privileges), as these may not be obvious to the reader.

The details should be separated into two sections:

1. The affected URL/endpoint
2. A method of triggering the vulnerability

If multiple areas are affected by the vulnerability, we should include a reference to each area. If there are many similar issues, then it's often acceptable to provide samples with a caveat that these are not the only areas where the issue occurs. In the latter case, we would recommend a systemic remediation.

## 5.2.7. Appendices, Further Information, and References

The final part of the report is the _Appendices_ section. Things that go here typically do not fit anywhere else in the report or are too lengthy or detailed to include inline. This includes long lists of compromised users or affected areas, large proof-of-concept code blocks, expanded methodology or technical write-ups, etc. A good rule to follow is if it's necessary for the report but would break the flow of the page, put it in an appendix.

We may wish to include a _Further Information_ section. In this section, we'd include things that may not be necessary for the main write-up but could reasonably provide value for the client. Examples would include articles that describe the vulnerability in more depth, standards for the remediation recommendation for the client to follow, and other methods of exploitation. If there is nothing that can add enough value, there is no reason to necessarily include this section.

_References_ can be a useful way to provide more insight for the client in areas not directly relevant to the testing we carried out. When providing references, we need to ensure we only use the most authoritative sources, and we should also ensure that we cite them properly.

In this Module we discussed various tools and practices which will come in handy while we write our penetration testing reports. However, just as within the penetration testing field itself, there is no "one tool to rule them all" for report writing either. With the vast amount of reporting and note-taking tools, we recommend experimenting with them to find what works for you and/or the client. In the long run, this will make report writing more comfortable and effective at the same time.

There are many aspects we need to keep in mind during penetration testing and note-taking is arguably one of the most important ones. We may end up working with thousands of computers, users, applications, etc. and remembering everything as we progress without documentation is close to impossible. Taking the time to document each step thoroughly will help us write a better report in the end. It will also make our penetration test more effective, allowing us to view the documentation as we go along to see what we have already done instead of repeating the steps.

Finally, we need to keep in mind who will read the report. The goal should be to make the report useful for all potential audiences within an organization, both technical and non-technical. We can do this by splitting the report up in different parts, using different levels of technical language in each of them. This will ensure that everyone gets an idea of what the outcome of the penetration test really was.
