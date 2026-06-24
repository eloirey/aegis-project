# Scenario 01 — Public S3 bucket → data exfiltration

> **MITRE ATT&CK:** T1530 (Data from Cloud Storage Object) · **Severity:** HIGH

## Context
S3 buckets are private by default, but a wrong ACL, bucket policy, or a disabled "Block
Public Access" setting can expose their contents to the entire internet. This is one of
the most common — and most damaging — cloud misconfigurations, behind countless real
data leaks.

## Attack
The `attack/demo_public_access.py` script demonstrates that the bucket's objects can be
read **anonymously**, i.e. with no AWS credentials at all — exactly what an external
attacker or a scanner bot would do.

```bash
./scripts/run-attack.sh 01-public-s3-bucket
```

## Detection
When the bucket is made public, AWS records the API call in CloudTrail
(`PutBucketAcl` / `PutBucketPolicy` / `PutPublicAccessBlock`). An EventBridge rule
matches that event and invokes the detection Lambda.

- **Source event:** CloudTrail S3 management event.
- **Time-to-detect target:** < 60 s.

## Response
The remediation Lambda:
1. Re-enables **Block Public Access** on the bucket.
2. Removes the offending public ACL/policy.
3. Publishes an enriched alert to SNS (with the ENS/NIS2/CIS mapping).

- **Time-to-remediate target:** < 10 s after detection.

## Compliance
See [`mapping.yaml`](mapping.yaml). Public S3 exposure relates to ENS information-
protection controls, NIS2 Art. 21 risk-management measures, and the CIS AWS S3 controls.

## Lessons (real-world prevention)
- Enable **account-level S3 Block Public Access**.
- Use an **SCP** to deny making buckets public org-wide.
- Detective control (this scenario) is the safety net when prevention fails.

---
### Build checklist
- [ ] `infra/main.tf` deploys the vulnerable bucket
- [ ] `attack/demo_public_access.py` proves anonymous read
- [ ] `detection/` rule + Lambda fire on the event
- [ ] `remediation/` Lambda locks it back down + alerts
- [ ] `mapping.yaml` filled and verified against official sources
