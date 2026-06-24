# 🗺️ Roadmap

This is a multi-month project meant to grow with you. Build it in phases — a working
small version beats an unfinished big one. Each phase ends with something you can
**demo and commit**.

## Phase 0 — Foundations (week 1)
- [ ] Create a **dedicated AWS sandbox account** (not your main one).
- [ ] Configure AWS CLI + an IAM user/role with the permissions you need.
- [ ] Set an **AWS Budget alert** (e.g. 5 €) so you never get surprised.
- [ ] Install Terraform, Python 3.12, and the project dependencies.
- [ ] Read `docs/architecture.md` and `docs/threat-model.md`.

## Phase 1 — Core backbone (week 2)
- [ ] Implement `infra/core`: CloudTrail (org/account trail), an EventBridge bus,
      an SNS topic for alerts, and an S3 bucket for logs.
- [ ] Subscribe your email to the SNS topic and confirm you receive a test alert.
- [ ] `./scripts/deploy.sh core` works end to end.

## Phase 2 — Scenario 01 end to end (weeks 3–4) ← **the MVP**
- [ ] `infra/`: Terraform that creates a deliberately public S3 bucket.
- [ ] `attack/`: a Python script that demonstrates anonymous read of the bucket.
- [ ] `detection/`: an EventBridge rule that fires on the relevant CloudTrail event
      (`PutBucketAcl` / `PutBucketPolicy` / public access change) → detection Lambda.
- [ ] `remediation/`: a Lambda that re-enables Block Public Access and notifies via SNS.
- [ ] `mapping.yaml`: map the finding to ENS / NIS2 / CIS.
- [ ] **Record yourself running it.** This clip is your portfolio gold.

> ✅ At the end of Phase 2 you already have a complete, demoable project.

## Phase 3 — Breadth (weeks 5–7)
- [ ] Scenario 02: over-privileged IAM → privilege escalation, detect + remediate.
- [ ] Scenario 03: security group open to `0.0.0.0/0` on port 22 → detect + remediate.
- [ ] Refactor anything repeated into `infra/modules` and `engine/`.

## Phase 4 — Visualization & story (weeks 8–9)
- [ ] Build the `dashboard/` (Streamlit is the fastest path) showing, per scenario:
      attack launched → detection time → remediation time → compliance controls hit.
- [ ] Record a **2–3 minute demo video** with narration. Embed it in the README.
- [ ] Export a clean architecture diagram to `docs/diagrams/architecture.png`.

## Phase 5 — Engineering polish (week 10+)
- [ ] GitHub Actions: run `tfsec` / `Checkov` on every PR (security scanning your own IaC
      is a great look — you scan the lab too).
- [ ] Unit tests for the engine (`tests/`).
- [ ] Complete `docs/compliance/ens-nis2-mapping.md`.
- [ ] Write each scenario README as a mini incident report.

## Stretch ideas (make it truly yours)
- Add a "detection-as-code" format (Sigma-style rules) instead of hardcoded logic.
- Add a GuardDuty-based detection path and compare it to your custom detections.
- Generate a PDF "compliance report" from the findings.
- Add a cost report showing the lab stays within Free Tier.
