# Scenario 01 — Public S3 bucket → data exposure

> **MITRE ATT&CK:** T1530 (Data from Cloud Storage Object) · **Severity:** HIGH · **Status:** complete
>
> Full lifecycle: **Deploy → Attack → Detect → Respond → Map**, end to end on real AWS.

## Context
S3 buckets are private by default, but a wrong bucket policy or a disabled *Block Public
Access* setting can expose their contents to the entire internet. It is one of the most
common — and most damaging — cloud misconfigurations, behind countless real data leaks.

## Layout
```
01-public-s3-bucket/
├── infra/          vulnerable bucket (Terraform)
├── attack/         anonymous-read proof
├── detection/      EventBridge rule + detection Lambda
├── remediation/    SNS-subscribed remediation Lambda
└── mapping.yaml    ENS / NIS2 / CIS mapping
```
Everything in this scenario runs in **eu-west-1** (S3 is regional).

## Deploy
The infra creates a bucket `aegis-project-lab-public-<random>` with all four Block Public
Access flags disabled, an anonymous-read bucket policy (`Principal "*"`, `s3:GetObject`),
and a decoy object `credentials.txt` holding fake content. The insecure settings are
deliberate; tfsec/Checkov findings here are expected.

```bash
cd scenarios/01-public-s3-bucket/infra
terraform init
terraform apply
BUCKET=$(terraform output -raw bucket_name)
```

## Attack
`attack/demo_public_access.py` reads the object **anonymously** — no AWS credentials at
all — using an `UNSIGNED` client, exactly what an external scanner or attacker would do.
Signed requests would authenticate as the owner and prove nothing.

```bash
python ../attack/demo_public_access.py --bucket "$BUCKET"
```

A successful anonymous read prints the decoy contents.

## Detect
Making the bucket public records a `PutBucketPolicy` call in CloudTrail. The EventBridge
rule `aegis-project-01-s3-public` matches that event and invokes the detection Lambda
`aegis-project-01-detect`, which raises the finding and publishes it to the
`aegis-project-findings` SNS topic.

```json
{ "finding_id": "PUBLIC_S3_BUCKET", "resource": "<bucket>", "actor": "<arn>", "action": "PutBucketPolicy" }
```

- **Source:** CloudTrail S3 management event → EventBridge → Lambda.
- **Latency:** near real time (CloudTrail management-event delivery, typically seconds to a couple of minutes).

## Respond
The remediation Lambda `aegis-project-01-remediate` is subscribed to the findings topic.
On a `PUBLIC_S3_BUCKET` finding it:
1. Re-enables **Block Public Access** (all four flags) — `s3:PutBucketPublicAccessBlock`.
2. Deletes the offending public policy — `s3:DeleteBucketPolicy`.

Detection and remediation are decoupled through SNS so a single finding can fan out to
several responders.

## Map
See [`mapping.yaml`](mapping.yaml). Summary:

| Framework | Controls |
|-----------|----------|
| **ENS** (RD 311/2022) | `op.acc.2` requisitos de acceso · `op.exp.2` configuración de seguridad · `op.exp.8` registro de actividad · `op.mon.1` detección de intrusión |
| **NIS2** (2022/2555) | Art. 21(2)(b) incident handling · (e) vulnerability handling · (i) access control |
| **CIS AWS** (v3.0.0) | 2.1.4 bucket-level Block Public Access · 2.1.1 account-level Block Public Access |

## Verify end-to-end
After deploying infra, detection and remediation, run the attack, then confirm the bucket
was locked back down:

```bash
aws logs tail /aws/lambda/aegis-project-01-detect --since 10m
aws logs tail /aws/lambda/aegis-project-01-remediate --since 10m
aws s3api get-public-access-block --bucket "$BUCKET"   # all four flags true after remediation
```

## Teardown
```bash
cd scenarios/01-public-s3-bucket/remediation && terraform destroy
cd ../detection   && terraform destroy
cd ../infra       && terraform destroy
```
Destroy scenario resources at the end of every session; the core backbone can stay up.

## Lessons (real-world prevention)
- Turn on **account-level** S3 Block Public Access so a single bucket can't override it.
- Use an **SCP** to deny making buckets public org-wide.
- This detective control is the safety net for when prevention fails.
