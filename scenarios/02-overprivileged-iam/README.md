# Scenario 02 — Over-privileged IAM → privilege escalation  *(planned)*

> **MITRE ATT&CK:** T1078 (Valid Accounts) · **Severity:** HIGH

Copy the structure of `01-public-s3-bucket/` and adapt:
- **infra/** — an IAM user/role with a dangerously broad policy (e.g. `iam:*` or
  `iam:PassRole` + `iam:CreatePolicyVersion`) that allows privilege escalation.
- **attack/** — a script that uses the over-broad permission to grant itself admin.
- **detection/** — match CloudTrail events like `AttachUserPolicy`, `PutUserPolicy`,
  `CreatePolicyVersion` performed by an unexpected principal.
- **remediation/** — detach/replace the offending policy; alert.
- **mapping.yaml** — ENS `op.acc` (control de acceso), NIS2 Art. 21, CIS AWS IAM controls.
