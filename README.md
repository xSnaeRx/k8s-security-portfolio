# k8s Security Portfolio
**Author:** xSnaeRx  
**Last Updated:** May 27, 2026  

---

## About

This repository documents hands-on Kubernetes security research completed through real-world CTF challenges and intentionally vulnerable lab environments. Each report covers a specific vulnerability, how it was discovered, its real-world impact, and how to remediate it.

The goal of this portfolio is to demonstrate practical, hands-on knowledge of Kubernetes security concepts including RBAC misconfigurations, container vulnerabilities, cloud metadata attacks, and network-level exploits.

---

## Lab Environments

| Environment | Description |
|---|---|
| [Wiz EKS Cluster Games](https://eksclustergames.com) | Real-world EKS CTF challenges covering cloud and Kubernetes security |
| [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat) | Intentionally vulnerable Kubernetes cluster for security training |

---

## Findings Reports

| Report | Vulnerability | Severity | Environment |
|---|---|---|---|
| [RBAC Least Privileges](./rbac-least-privileges-findings.md) | Overly permissive service account exposing cluster secrets via REST API | High | Kubernetes Goat |
| [SSRF in the Kubernetes World](./ssrf-kubernetes-world-findings.md) | Server Side Request Forgery allowing access to internal cluster services | Critical | Kubernetes Goat |

---

## Skills Demonstrated

- Kubernetes RBAC auditing and exploitation
- Server Side Request Forgery (SSRF) in containerized environments
- Direct Kubernetes API server interaction via REST
- Container image layer analysis and secrets extraction
- AWS Instance Metadata Service (IMDS) credential theft
- Docker registry authentication and image inspection
- kubectl, crane, curl, git, base64 decoding
- Professional security findings documentation

---

## Tools Used

| Tool | Purpose |
|---|---|
| `kubectl` | Kubernetes cluster interaction |
| `crane` | Container image inspection and registry authentication |
| `curl` | Direct REST API calls |
| `AWS CLI` | Cloud credential and IAM interaction |
| `base64` | Decoding encoded secrets |
| `git` | Source code and commit history analysis |
| `kind` | Local Kubernetes cluster via Docker |

---

## Background

This research was conducted as part of self-directed Kubernetes security training, progressing from guided CTF challenges (Wiz EKS Cluster Games) to independent exploration of vulnerable lab environments (Kubernetes Goat). Each scenario was approached without walkthroughs where possible, prioritizing genuine problem-solving over guided completion.

---

> *"Security is not a product, but a process."* — Bruce Schneier
