# John the Ripper

- Password cracker using brute force or dictionary attacks

## Types of Attacks

- Dictionary
  - Using a pre-generated list of words and phrases (dictionary) to attempt to crack a password.
  - Words in the wordlist are hashed, and the hashes are compared with the hashed passwords you're trying to crack.
- Brute Force
  - This is where every possible permutation of characters that form a password are guessed.
- Rainbow Table
  - Basically a table of hashes and their corresponding passwords.
  - For this to be effective, you have to have a table with a lot of hashes.

## Cracking Modes

### Single

- Brute force mode.

```bash
zombear@htb[/htb]$ john --format=sha256 hashes_to_crack.txt
```

### Wordlist

- Dictionary attack that uses multiple word lists.
- Multiple wordlists can be specified by separating them with a comma.

```bash
zombear@htb[/htb]$ john --wordlist=wordlist.txt --rules hashes.txt
```

### Incremental

- Advanced John mode used to crack passwords using a character set.
- Most effective + most time consuming.
- Difference between this and wordlist mode is that `John generates guess on the fly` in incremental mode.

## Cracking Files

- Automatically detects the encrypted file's format and tries to crack it.

### Syntax

```bash
# cry0l1t3@htb:~$ <tool> <file_to_crack> > file.hash
# Convert pdf file for john
cry0l1t3@htb:~$ pdf2john server_doc.pdf > server_doc.hash

# crack the hash file
cry0l1t3@htb:~$ john server_doc.hash
```

- Find John's tools

```bash
zombear@htb[/htb]$ locate *2john*
```
