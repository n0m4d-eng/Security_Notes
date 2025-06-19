# NFS

---

tags:

- cpts
- cybersecurity
- info gathering

---

# Cheat Sheet

```
# Show available NFS Shares
showmount -e [target ip]

# Mounting NFS Shares
sudo mount -t nfs [target  ip]:/ ./local-taget-folder/ -o nolock

# Unmount the NFS share
sudo umount ./target-NFS
```

# Concepts

## Basic Info

- Network File System

- An internet standard that governs the procedures in a distributed ssytem

- Same purpose as SMB, but uses a different protocol.

- Used between Unix and Linux systems, meaning NFS clients can't communicate directly with SMB servers.

- Based on the `Open Network Computing Remote Procedure Call` (ONC-PRC/SUN-RPC) protocol.

- Uses `External Data Representation` (XDR) for system-independent exchange of data.

- Exposed on `TCP/UDP port 111` 

- NFSv4 uses `TCP/UDP port 2049`

## Versions

| **Version** | **Features**                                                                                                                                                                                                                                                                     |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NFSv2`     | It is older but is supported by many systems and was initially operated entirely over UDP.                                                                                                                                                                                       |
| `NFSv3`     | It has more features, including variable file size and better error reporting, but is not fully compatible with NFSv2 clients.                                                                                                                                                   |
| `NFSv4`     | It includes Kerberos, works through firewalls and on the Internet, <br>no longer requires portmappers, supports ACLs, applies state-based <br>operations, and provides performance improvements and high security. It <br>is also the first version to have a stateful protocol. |

## Default Configuration

- `/etc/exports` file contains a table of physical filesystems on an NFS server accessible by the clients.

| **Option**         | **Description**                                                                                                                             |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `rw`               | Read and write permissions.                                                                                                                 |
| `ro`               | Read only permissions.                                                                                                                      |
| `sync`             | Synchronous data transfer. (A bit slower)                                                                                                   |
| `async`            | Asynchronous data transfer. (A bit faster)                                                                                                  |
| `secure`           | Ports above 1024 will not be used.                                                                                                          |
| `insecure`         | Ports above 1024 will be used.                                                                                                              |
| `no_subtree_check` | This option disables the checking of subdirectory trees.                                                                                    |
| `root_squash`      | Assigns all permissions to files of root UID/GID 0 to the UID/GID of anonymous, which prevents `root` from accessing files on an NFS mount. |

## Footprinting

- TCP ports `111` and  `2049` are essential

- ```shell-session
  sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049- cpts
  ```
