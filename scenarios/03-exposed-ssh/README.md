# Scenario 03 — Exposed SSH (port 22 open to the world)

> **MITRE ATT&CK:** T1133 (External Remote Services) · **Severity:** HIGH · **Status:** complete
>
> Full lifecycle: **Deploy → Attack → Detect → Respond → Map**, end to end on real AWS.

## Context
Leaving SSH (port 22) open to `0.0.0.0/0` is one of the most common — and most scanned —
cloud mistakes. Bots sweep the internet for it continuously. A single over-permissive
security group rule turns a host into a brute-force and exploitation target.

## Layout
```
03-exposed-ssh/
├── infra/          EC2 host + security group, born closed (Terraform)
├── attack/         opens port 22 to the world and proves reachability
├── detection/      EventBridge rule + detection Lambda
├── remediation/    SNS-subscribed revoke Lambda
└── mapping.yaml    ENS / NIS2 / CIS mapping
```
Everything in this scenario runs in **eu-west-1** (EC2 is regional — no us-east-1 detour
like the IAM scenario).

## Deploy
The infra brings up a `t3.micro` Amazon Linux 2023 host (default VPC, public IP) and a
security group `aegis-project-lab-ssh` that is **born closed** — egress only, no SSH
ingress. The dangerous rule is added by the attack, not baked in, so it fires a real
`AuthorizeSecurityGroupIngress` event. Expected tfsec/Checkov findings.

```bash
cd scenarios/03-exposed-ssh/infra
terraform init
terraform apply
SG=$(terraform output -raw security_group_id)
IP=$(terraform output -raw instance_public_ip)
```

> **Cost note:** `t3.micro` is Free Tier eligible, but AWS now bills the public IPv4 address
> (~$0.005/h ≈ cents if torn down per session). Run `terraform destroy` at the end.

## Attack
`attack/demo_exposed_ssh.py` opens `tcp/22` to `0.0.0.0/0` and proves the exposure instead
of asserting it: it does a TCP connect to the host from outside before and after, and reads
the SSH banner once the port is reachable.

```bash
python ../attack/demo_exposed_ssh.py --security-group-id "$SG" --public-ip "$IP"
# -> [!] SUCCESS - port 22 is now open to 0.0.0.0/0  (Service responded: SSH-2.0-OpenSSH_...)
```

## Detect
The rule change records an `AuthorizeSecurityGroupIngress` call in CloudTrail. The
EventBridge rule `aegis-project-03-exposed-ssh` invokes the detection Lambda
`aegis-project-03-detect`, which inspects the rule and raises a finding only when it
reaches port 22 from `0.0.0.0/0` or `::/0`. Narrower rules (a specific office IP, or a
different port) are ignored — detection is on content, not on the actor.

```json
{ "finding_id": "EXPOSED_SSH", "resource": "<sg-id>", "actor": "<arn>", "action": "AuthorizeSecurityGroupIngress",
  "offending_rule": { "protocol": "tcp", "from_port": 22, "to_port": 22, "v4": ["0.0.0.0/0"], "v6": [] } }
```

The finding is published to the `aegis-project-findings` SNS topic.

## Respond
The remediation Lambda `aegis-project-03-remediate` is subscribed to the findings topic.
It rebuilds the exact rule from `offending_rule` and calls `ec2:RevokeSecurityGroupIngress`,
removing **only** that rule and leaving the rest of the group intact — surgical and
reversible. Its role can only revoke rules on security groups tagged for this project.

## Map
See [`mapping.yaml`](mapping.yaml). Summary:

| Framework | Controls |
|-----------|----------|
| **ENS** (RD 311/2022) | `mp.com.1` perímetro seguro · `op.exp.2` configuración de seguridad · `op.exp.8` registro de actividad · `op.mon.1` detección de intrusión |
| **NIS2** (2022/2555) | Art. 21(2)(i) access control · (e) vulnerability handling · (b) incident handling |
| **CIS AWS** (v3.0.0, §5 Networking) | 5.2 no SG ingress from 0.0.0.0/0 to remote admin ports · 5.3 same for ::/0 |

## Verify end-to-end
After deploying infra, detection and remediation, run the attack and watch it self-heal
(allow a minute or two for CloudTrail event delivery):

```bash
aws logs tail /aws/lambda/aegis-project-03-detect    --region eu-west-1 --since 10m
aws logs tail /aws/lambda/aegis-project-03-remediate --region eu-west-1 --since 10m
aws ec2 describe-security-groups --group-ids "$SG" --region eu-west-1 \
  --query "SecurityGroups[0].IpPermissions"   # [] after remediation
```

To show the loop closing, re-check reachability — the port that was open is closed again:

```bash
python -c "import socket; s=socket.socket(); s.settimeout(5); print('OPEN' if s.connect_ex(('$IP',22))==0 else 'CLOSED')"
# -> CLOSED
```

## Teardown
```bash
cd scenarios/03-exposed-ssh/remediation && terraform destroy
cd ../detection   && terraform destroy
cd ../infra       && terraform destroy
```
This also terminates the instance and deletes the group, closing any leftover exposure.

## Lessons (real-world prevention)
- Never open admin ports (22/3389) to `0.0.0.0/0`; use a bastion, VPN, or SSM Session Manager.
- Restrict the default security group of every VPC to deny all (CIS).
- This detective/responsive control is the safety net for when a rule slips through review.
