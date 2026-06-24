# 🎯 Threat model

A short, honest threat model. Keep it pragmatic — interviewers value clear reasoning
over exhaustive checklists.

## Scope
Aegis Project is a **training/lab range**, not a production security product. The "system under
test" is a dedicated AWS sandbox account containing intentionally vulnerable resources.

## Assets
- The vulnerable resources (S3 data, IAM credentials, EC2 instances).
- The CloudTrail logs (source of truth for detection).
- The AWS account itself (billing, blast radius).

## Adversaries we simulate
| Adversary | Goal | Scenario(s) |
|-----------|------|-------------|
| External anonymous user | Read exposed data | 01 — public S3 |
| Compromised low-priv principal | Escalate privileges | 02 — IAM |
| Internet scanner / bot | Find & brute-force open ports | 03 — exposed SSH |

## Risks introduced by the lab itself (and mitigations)
| Risk | Mitigation |
|------|------------|
| Real attackers find the deliberately exposed resources | Dedicated sandbox account; short-lived; `destroy` after each session |
| Runaway cost | AWS Budget alert; Free-Tier sizing; tear-down scripts |
| Lab credentials leak | Least-privilege CI; never commit secrets; `.gitignore` for tfstate/keys |
| Cross-account blast radius | Account isolation; no trust relationships to other accounts |

## What is explicitly out of scope
- Persistence/availability attacks (DoS).
- Anything that would touch resources outside the sandbox account.
- Real malware or live C2 — attacks are benign demonstrations of the technique.

## MITRE ATT&CK mapping
Each scenario README names the ATT&CK technique it demonstrates (e.g. T1530, T1078,
T1110). This keeps the offensive side grounded in a recognised taxonomy.
