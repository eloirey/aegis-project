# Roadmap

Aegis was built in phases — a working small version beats an unfinished big one, and each phase ended with something demoable and committed. Phases 0–5 are **done**; the range is published and verified against real AWS. What follows is where it goes next.

## Shipped

### Phase 0 — Foundations
Dedicated AWS sandbox account, AWS CLI + scoped IAM, a Budget alert, and the toolchain (Terraform, Python 3.12). Architecture and threat model written up in `docs/`.

### Phase 1 — Core backbone
`infra/core` deployed end to end: a multi-region **CloudTrail** trail, the **EventBridge** bus, the **SNS** `aegis-project-alerts` topic (email subscription confirmed), an S3 log bucket, and the **DynamoDB** findings table. `./scripts/deploy.sh core` works.

### Phase 2 — Scenario 01 (the MVP)
Public S3 bucket, end to end: vulnerable Terraform → scripted attack → EventBridge + detection Lambda → remediation Lambda (Block Public Access restored) → `mapping.yaml`. The first complete deploy → attack → detect → respond → map loop.

### Phase 3 — Breadth
Two more scenarios, each verified against real AWS:
- **02 — Over-privileged IAM** → privilege escalation, contained with a reversible explicit-deny quarantine. Runs in `us-east-1` (IAM is global) while writing findings cross-region.
- **03 — Exposed SSH** (`0.0.0.0/0` on port 22) → the offending ingress rule is revoked surgically, leaving the rest of the security group intact.

### Phase 4 — Visualization & story
- A multipage **Streamlit** dashboard: a real-time **Live Findings** view (detected → remediated) and a **Compliance Coverage** view.
- A **2-minute demo video** with narration, embedded in the README.
- A clean **architecture diagram** at `docs/diagrams/architecture.png`.

### Phase 5 — Engineering polish
- **GitHub Actions** running `tfsec` and `Checkov` on every push (IaC security scanning — the lab scans itself).
- A **pytest** suite for the engine (mapping + persistence, mocked with `moto`).
- The full **compliance mapping** documented, with a rationale per control.
- A **DynamoDB persistence layer** (`engine/store`) recording the finding lifecycle, powering the live dashboard.

## What's next

- **More scenarios** — the pattern extends by adding a folder; each new one covers more ENS / NIS2 / CIS controls (e.g. unencrypted resources, disabled logging, public RDS).
- **Resilience** — dead-letter queues and retries on the detection path, so a transient Lambda failure never silently drops a finding.
- **A blue-team companion project** — threat hunting / a mini-SIEM operating *over* this infrastructure: Aegis builds the automated defence; the next project is about operating and hunting within it.

## Stretch ideas

- A **detection-as-code** format (Sigma-style rules) instead of logic baked into the Lambdas.
- A **GuardDuty**-based detection path, compared side by side with the custom detections.
- A generated **PDF compliance report** built from the findings.
- A **cost report** proving the lab stays within the Free Tier.
