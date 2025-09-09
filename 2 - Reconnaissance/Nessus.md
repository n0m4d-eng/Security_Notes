**Note:** The use of Nessus is _forbidden_ during the exam. This tool should be used only in your personal lab environment for practice purposes.

Nessus is a powerful vulnerability scanning tool that can identify vulnerabilities, misconfigurations, and compliance issues. Here's how you can install and set it up:

1.  **Download Nessus**

```bash
Go to the Nessus website https://www.tenable.com/downloads/nessus?loginAttempted=true and select the platform.

Download the installer to your local machine.
```

2.  **Verify the Download**

```bash
#  It's important to verify the integrity of the download with `sha256sum`.
cd ~/Downloads
echo "[sha256_sum_found_in_website] Nessus-10.5.0-debian10_amd64.deb" > sha256sum_nessus
sha256sum -c sha256sum_nessus

# Expected Output: OK
```

3.  **Install Nessus**

```bash
sudo apt install ./Nessus-10.5.0-debian10_amd64.deb
```

4.  **Start Nessus**

```bash
sudo systemctl start nessusd.service

# Then, visit the Nessus GUI at https://127.0.0.1:8834 to configure the scanner.
```