---
date: "20-06-2025"
tags:
---

```table-of-contents
```

# What it is

# Enumerating

# Exploiting

# Remidiating

Some kubelet useful API to curl:

http://localhost:10255/pods
http://localhost:10255/stats/summary
http://localhost:10255/metrics

Author: Eviatar Gerzi
Version: 1.13
GitHub: https://github.com/cyberark/kubesploit

Description:
kubeletctl is command line utility that implements kuebelt's API.
It also provides scanning for opened kubelet APIs and search for potential RCE on containers.

You can view examples from each command by using the -h\--help flag like that: kubeletctl run -h
Examples:
// List all pods from kubelet
kubeletctl pods --server 123.123.123.123

// List all pods from kubelet with token
kubeletctl pods --token <JWT_token> --server 123.123.123.123

// List all pods from kubelet with token file
kubeletctl pods --token-file /var/run/secrets/kubernetes.io/serviceaccount/token --server 123.123.123.123

// Searching for service account token in each accessible container
kubeletctl scan token --server 123.123.123.123

// Searching for pods/containers vulnerable to RCE
kubeletctl scan rce --server 123.123.123.123

// Run "ls /" command on pod my-nginx-pod/nginx in thedefault namespace
kubeletctl run "ls /" --namespace default --pod my-nginx-pod --container nginx --server 123.123.123.123

// Run "ls /" command on all existing pods in a node
kubeletctl.exe run "ls /" --all-pods --server 123.123.123.123

// With certificates
kubeletctl.exe pods -s <node_ip> --cacert C:\Users\myuser\certs\ca.crt --cert C:\Users\myuser\certs\kubelet-client-current.pem --key C:\Users\myuser\certs\kubelet-client-current.pem

Usage:
kubeletctl [flags]
kubeletctl [command]

Available Commands:
attach Attach to a container
checkpoint Taking a container snapshot
configz Return kubelet's configuration.
containerLogs Return container log
cri Run commands inside a container through the Container Runtime Interface (CRI)
debug Return debug information (pprof or flags)
exec Run commands inside a container
healthz Check the state of the node
help Help about any command
log Return the log from the node.
metrics Return resource usage metrics (such as container CPU, memory usage, etc.)
pid2pod That shows how Linux process IDs (PIDs) can be mapped to Kubernetes pod metadata
pods Get list of pods on the node
portForward Attach to a container
run Run commands inside a container
runningpods Returns all pods running on kubelet from looking at the container runtime cache.
scan Scans for nodes with opened kubelet API
spec Cached MachineInfo returned by cadvisor
stats Return statistical information for the resources in the node.
version Print the version of the kubeletctl

Flags:
--cacert string CA certificate (example: /etc/kubernetes/pki/ca.crt )
--cert string Private key (example: /var/lib/kubelet/pki/kubelet-client-current.pem)
--cidr string A network of IP addresses (Example: x.x.x.x/24)
-k, --config string KubeConfig file
-c, --container string Container name
-h, --help help for kubeletctl
--http Use HTTP (default is HTTPS)
-i, --ignoreconfig Ignore the default KUBECONFIG environment variable or location ~/.kube
--key string Digital certificate (example: /var/lib/kubelet/pki/kubelet-client-current.pem)
-n, --namespace string pod namespace
-p, --pod string Pod name
--port string Kubelet's port, default is 10250
-r, --raw Prints raw data
-s, --server string Server address (format: x.x.x.x. For Example: 123.123.123.123)
-t, --token string Service account Token (JWT) to insert
-f, --token-file string Service account Token (JWT) file path
-u, --uid string Pod UID

Use "kubeletctl [command] --help" for more information about a command.
