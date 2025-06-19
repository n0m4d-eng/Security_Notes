# Hashcat Cheatsheet

## Overview

Hashcat is a powerful password recovery tool that supports a wide variety of hash types and utilizes multiple attack modes. It can leverage CPU, GPU, and distributed computing for high-speed cracking.

### Key Features:

- Supports multiple hash algorithms (MD5, SHA1, NTLM, etc.)
- Multiple attack modes (Dictionary, Brute-force, Hybrid, etc.)
- Can utilize CPU, GPU, and FPGA acceleration

## Installation

### Linux

```bash
sudo apt update && sudo apt install hashcat
```

### Windows

1. Download Hashcat from [https://hashcat.net/hashcat/](https://hashcat.net/hashcat/)
2. Extract the archive and use the command prompt to navigate to the folder.

---

## Basic Usage

### Checking Supported Hash Modes

```bash
hashcat --help | grep -i hash-mode
```

### Identifying Hash Type

```bash
hashid -m <hash>
```

### Running a Basic Attack

```bash
hashcat -m <hash_mode> -a <attack_mode> -o output.txt hash.txt wordlist.txt
```

### Stopping and Resuming Cracking

```bash
hashcat --restore
```

### Running in Benchmark Mode

```bash
hashcat -b
```

---

## Attack Modes

| Mode | Description                  |
| ---- | ---------------------------- |
| 0    | Straight (Dictionary Attack) |
| 1    | Combination Attack           |
| 3    | Brute-force Attack           |
| 6    | Hybrid Wordlist + Mask       |
| 7    | Hybrid Mask + Wordlist       |

---

## Hash Modes

| Mode | Hash Type |
| ---- | --------- |
| 0    | MD5       |
| 100  | SHA1      |
| 1400 | SHA256    |
| 1800 | SHA512    |
| 1000 | NTLM      |
| 5600 | NetNTLMv2 |

---

## Common Commands

### Dictionary Attack

```bash
hashcat -m 0 -a 0 -o cracked.txt hashes.txt rockyou.txt
```

### Brute-force Attack

```bash
hashcat -m 0 -a 3 -o cracked.txt hashes.txt ?a?a?a?a?a?a
```

### Mask Attack

```bash
hashcat -m 0 -a 3 -o cracked.txt hashes.txt ?l?l?l?l?d?d
```

### Hybrid Attack

```bash
hashcat -m 0 -a 6 -o cracked.txt hashes.txt rockyou.txt ?d?d?d
```

### Using GPU Acceleration

```bash
hashcat -m 1000 -a 0 --force --opencl-device-types 1,2 hashes.txt rockyou.txt
```

### Save Progress and Restore

```bash
hashcat --session=mySession --restore

```
