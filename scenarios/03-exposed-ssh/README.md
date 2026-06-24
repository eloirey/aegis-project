# Scenario 03 — Exposed SSH (0.0.0.0/0) → brute force  *(planned)*

> **MITRE ATT&CK:** T1110 (Brute Force) · **Severity:** MEDIUM/HIGH

Copy the structure of `01-public-s3-bucket/` and adapt:
- **infra/** — an EC2 instance with a security group allowing port 22 from 0.0.0.0/0.
- **attack/** — demonstrate the exposure (e.g. show the open port; simulate repeated
  auth attempts in a controlled way — keep it benign and legal).
- **detection/** — match `AuthorizeSecurityGroupIngress` opening 22 to the world, and/or
  VPC Flow Logs / GuardDuty brute-force findings.
- **remediation/** — revoke the 0.0.0.0/0 rule; restrict to a known IP; alert.
- **mapping.yaml** — ENS `mp.com` (protección de las comunicaciones), NIS2 Art. 21,
  CIS AWS networking controls.
