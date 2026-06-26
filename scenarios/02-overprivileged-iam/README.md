# Scenario 02 — Over-privileged IAM → privilege escalation

> **MITRE ATT&CK:** T1078 (Valid Accounts) · T1098 (Account Manipulation) · **Severity:** HIGH · **Status:** complete
>
> Full lifecycle: **Deploy → Attack → Detect → Respond → Map**, end to end on real AWS.

## Context
A single over-permissioned IAM identity is enough to take over an account. A user that can
manage its own IAM policies can attach `AdministratorAccess` to itself — escalating from a
narrow, innocuous-looking grant to full admin with one API call. This scenario reproduces
that self-escalation, detects it by **policy content**, and contains it with a **reversible
quarantine**.

## Layout
```
02-overprivileged-iam/
├── infra/          self-escalatable IAM user (Terraform)
├── attack/         self-escalation to AdministratorAccess
├── detection/      EventBridge rule + detection Lambda
├── remediation/    SNS-subscribed quarantine Lambda
└── mapping.yaml    ENS / NIS2 / CIS mapping
```

### Region split (important)
IAM is a **global** service: its CloudTrail management events are delivered to EventBridge
in **us-east-1**, not in the lab's eu-west-1 region. So:

| Component | Region |
|-----------|--------|
| `infra/` — the IAM user | eu-west-1 |
| `detection/` + `remediation/` — rule, Lambdas, findings topic | **us-east-1** |

The core multi-region trail is what makes those global events available to capture.

## Deploy
The infra creates the user `aegis-project-lab-developer` with an inline policy granting
`iam:AttachUserPolicy` / `iam:PutUserPolicy` **scoped to its own ARN** — the classic
escalation primitive — plus an access key that stands in for a leaked credential. The
self-scoping keeps the lab's blast radius to exactly the self-escalation path. Expected
tfsec/Checkov findings.

```bash
# 1) vulnerable identity (eu-west-1)
cd scenarios/02-overprivileged-iam/infra
terraform init && terraform apply

# 2) detection + remediation (us-east-1, default in their providers)
cd ../detection   && terraform init && terraform apply
cd ../remediation && terraform init && terraform apply
```

## Attack
`attack/demo_privilege_escalation.py` authenticates as the leaked key and attaches
`AdministratorAccess` to itself. It proves the escalation instead of asserting it: an
`iam:ListUsers` call is denied before and succeeds after.

```bash
cd ../infra
AK=$(terraform output -raw lowpriv_access_key_id)
SK=$(terraform output -raw lowpriv_secret_access_key)
python ../attack/demo_privilege_escalation.py --access-key-id "$AK" --secret-access-key "$SK"
# -> [!] SUCCESS - privilege escalated to administrator
```

## Detect
The escalation records an `AttachUserPolicy` call in CloudTrail. The EventBridge rule
`aegis-project-02-iam-privileged` (us-east-1) funnels `AttachUserPolicy`,
`AttachRolePolicy`, `PutUserPolicy` and `PutRolePolicy` to the detection Lambda
`aegis-project-02-detect`, which inspects the **policy content** — `AdministratorAccess`
for managed attaches, or an inline statement allowing `Action "*"` on `Resource "*"`. It
raises a finding only for admin-equivalent grants, so benign changes (e.g. attaching
`ReadOnlyAccess`) are ignored. Detection is on content, not on the actor.

```json
{ "finding_id": "PRIVILEGED_IAM", "resource": "aegis-project-lab-developer", "actor": "<arn>", "action": "AttachUserPolicy", "principal_type": "user" }
```

The finding is published to the `aegis-project-findings` SNS topic (us-east-1).

## Respond
The remediation Lambda `aegis-project-02-remediate` is subscribed to the findings topic.
It attaches a reversible inline policy `aegis-quarantine` with an explicit `Deny` over the
escalation, persistence and self-rescue actions (`iam:Attach*`, `iam:Put*Policy`,
`iam:CreateAccessKey`, `iam:Create*`, `iam:Detach*`, `iam:Delete*Policy`, …).

An explicit Deny always beats any Allow, so this neutralises the escalation **without
detaching anything**: the `AdministratorAccess` grant stays in place (reversible for false
positives), only the kill chain is cut, and the compromised identity can't remove the
quarantine itself — the operator can. Removing the inline policy fully reverts the action.

## Map
See [`mapping.yaml`](mapping.yaml). Summary:

| Framework | Controls |
|-----------|----------|
| **ENS** (RD 311/2022) | Art. 20 mínimo privilegio · `op.acc.4` gestión de derechos de acceso · `op.acc.3` segregación de funciones · `op.exp.8` registro de actividad · `op.mon.1` detección de intrusión |
| **NIS2** (2022/2555) | Art. 21(2)(i) access control · (b) incident handling · (e) vulnerability handling |
| **CIS AWS** (v3.0.0, IAM) | 1.16 no full `*:*` admin policies attached · 1.15 permissions only through groups |

## Verify end-to-end
After the attack, confirm the auto-remediation (allow 2–3 min for IAM global event
delivery):

```bash
aws logs tail /aws/lambda/aegis-project-02-detect    --region us-east-1 --since 10m
aws logs tail /aws/lambda/aegis-project-02-remediate --region us-east-1 --since 10m
aws iam list-user-policies --user-name aegis-project-lab-developer   # shows aegis-quarantine
```

To show the quarantine actually blocks: detach admin (as operator) and re-run the attack —
the same key can no longer escalate.

```bash
aws iam detach-user-policy --user-name aegis-project-lab-developer \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
python ../attack/demo_privilege_escalation.py --access-key-id "$AK" --secret-access-key "$SK"
# -> [+] Escalation blocked
```

## Teardown
Two regions — destroy all three stacks:

```bash
cd scenarios/02-overprivileged-iam/remediation && terraform destroy   # us-east-1
cd ../detection   && terraform destroy                                # us-east-1
cd ../infra       && terraform destroy                                # eu-west-1
```
`force_destroy` on the user clears the `aegis-quarantine` and `AdministratorAccess`
attachments left out of Terraform state, so the infra teardown stays clean.

## Lessons (real-world prevention)
- Never grant an identity IAM-write over itself; use **permissions boundaries** to cap it.
- Prefer **groups/roles** over policies attached directly to users (CIS 1.15).
- Alert on, and auto-contain, any attach of admin-equivalent policies — prevention plus this
  detective/responsive control.
