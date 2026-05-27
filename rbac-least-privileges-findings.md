# Kubernetes Security Lab: RBAC Least Privileges
**Author:** xSnaeRx  
**Date:** May 27, 2026  
**Lab Environment:** Kubernetes Goat on kind (Kubernetes in Docker) via WSL2  
**Scenario:** RBAC Least Privileges  

---

## Executive Summary

During this lab exercise, a misconfigured Kubernetes service account was identified in the `big-monolith` namespace. The service account `big-monolith-sa` was granted excessive permissions, allowing it to list and read secrets across the namespace. By leveraging the service account token automatically mounted into the pod, direct REST API calls to the Kubernetes API server were used to extract two sensitive secrets that should not have been accessible.

---

## Environment

| Component | Details |
|---|---|
| Cluster | kind (Kubernetes in Docker) |
| Namespace | `big-monolith` |
| Pod | `hunger-check-deployment-7897964f79-wl76t` |
| Service Account | `system:serviceaccount:big-monolith:big-monolith-sa` |
| API Server | `https://10.96.0.1:443` |

---

## Findings

### Finding 1 — Overly Permissive Service Account (RBAC Misconfiguration)

**Severity:** High

**Description:**  
The service account `big-monolith-sa` was granted permission to list and read secrets within the `big-monolith` namespace. This violates the principle of least privilege — the service account only needed to run the application, not access secrets.

**How It Was Discovered:**  
After exec-ing into the pod, the Kubernetes service account token was located at the default mount path:

```
/var/run/secrets/kubernetes.io/serviceaccount/token
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
/var/run/secrets/kubernetes.io/serviceaccount/namespace
```

The API server address was identified via environment variables injected into the pod:

```bash
env | grep -i kube
# KUBERNETES_SERVICE_HOST=10.96.0.1
# KUBERNETES_SERVICE_PORT=443
```

A direct REST API call was then made to the Kubernetes API server using the mounted token and CA certificate:

```bash
curl --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  https://10.96.0.1:443/api/v1/namespaces/big-monolith/secrets
```

**Result:**  
The API server returned a full list of secrets in the `big-monolith` namespace, confirming the service account had excessive read permissions.

---

### Finding 2 — Sensitive Secrets Exposed via API

**Severity:** Critical

**Description:**  
Two sensitive API keys were retrieved from the Kubernetes secrets store using the misconfigured service account.

**Secrets Retrieved:**

| Secret Name | Key | Decoded Value |
|---|---|---|
| `vaultapikey` | `k8svaultapikey` | `k8s-goat-85057846a8046a25b35f38f3a2649dce` |
| `webhookapikey` | `k8swebhookapikey` | `k8s-goat-dfcf630539553ecf9586fdfa1968fec` |

**Decoding Method:**
```bash
echo "azhzLWdvYXQtODUwNTc4NDZhODA0NmEyNWIzNWYzOGYzYTI2NDlkY2U=" | base64 -d
echo "azhzLWdvYXQtZGZjZjYzMDUzOTU1M2VjZjk1ODZmZGZkYTE5NjhmZWM=" | base64 -d
```

---

## Attack Chain

```
Pod Exec Access
      ↓
Located mounted service account token
      ↓
Identified API server via environment variables
      ↓
Made direct REST API call to Kubernetes API server
      ↓
Listed secrets in big-monolith namespace
      ↓
Decoded base64 encoded secret values
      ↓
Retrieved vault and webhook API keys
```

---

## Root Cause

The `big-monolith-sa` service account was bound to a role that granted `get` and `list` permissions on `secrets` in the `big-monolith` namespace. This is a violation of the **principle of least privilege** — the application had no legitimate need to read Kubernetes secrets directly.

Additionally, Kubernetes automatically mounts service account tokens into every pod by default, meaning any process running inside the pod can use that token to authenticate to the API server.

---

## Remediation

### 1. Remove Secret Access from the Service Account
Audit and remove `get`/`list` permissions on secrets from the `big-monolith-sa` role:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: big-monolith-role
  namespace: big-monolith
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
# Do NOT include secrets here unless explicitly required
```

### 2. Disable Automatic Service Account Token Mounting
If the pod does not need to talk to the Kubernetes API, disable token mounting:

```yaml
spec:
  automountServiceAccountToken: false
```

### 3. Apply Least Privilege Across All Service Accounts
Audit all service accounts and their role bindings:

```bash
kubectl get rolebindings,clusterrolebindings -A -o yaml | grep -i secret
```

### 4. Use Kubernetes Audit Logging
Enable audit logging to detect unusual API server calls, especially reads on secrets.

---

## Key Takeaway

> A service account with excessive permissions combined with an automatically mounted token gives any attacker who gains pod access a direct path to sensitive secrets — without needing to escalate privileges or break out of the container.

---

## References

- [Kubernetes RBAC Documentation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat)
- [MITRE ATT&CK - Container Administration Command](https://attack.mitre.org/techniques/T1609/)
