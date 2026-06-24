<div align="center">

# Aegis Project

### A self-healing cloud security range for AWS

**Attack, detect, auto-remediate, and map every finding to ENS & NIS2.**

<sub>Deploy intentionally vulnerable AWS infrastructure, attack it, watch it detect and remediate itself — with every finding tied to the Spanish ENS and EU NIS2 frameworks.</sub>

[![Terraform](https://img.shields.io/badge/IaC-Terraform-7B42BC?logo=terraform&logoColor=white)]()
[![AWS](https://img.shields.io/badge/Cloud-AWS-FF9900?logo=amazonaws&logoColor=white)]()
[![Python](https://img.shields.io/badge/Engine-Python%203.12-3776AB?logo=python&logoColor=white)]()
[![Security Scan](https://img.shields.io/badge/IaC%20Scan-Checkov%20%7C%20tfsec-success)]()
[![License](https://img.shields.io/badge/License-MIT-blue)]()

</div>

> **Warning:** This project deploys deliberately insecure cloud resources. It is meant to be run in an **isolated, dedicated AWS sandbox account** and destroyed afterwards. Never deploy it in a production account. See [Safety & Cost](#safety--cost).

---

## Why this project exists

Most "cloud security" portfolio projects are either a thin wrapper around an existing scanner or a static "I deployed a web app on AWS" demo. **Aegis Project tells a full story instead.** Each scenario walks through the complete lifecycle of a real cloud security incident:

```
  ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
  │  DEPLOY  │ ──▶ │  ATTACK  │ ──▶ │  DETECT  │ ──▶ │ RESPOND  │ ──▶ │   MAP    │
  │ vuln IaC │     │ scripted │     │ CloudTrail│    │  auto-   │     │ ENS/NIS2 │
  │ Terraform│     │  exploit │     │ EventBridge│    │ remediate│     │   /CIS   │
  └──────────┘     └──────────┘     └──────────┘     └──────────┘     └──────────┘
```

You don't just *talk* about misconfigurations — you reproduce them, exploit them, catch them, and fix them automatically, end to end.

## The differentiator: compliance-as-context

Every detection in Aegis Project is enriched with the control it violates in:

- **ENS** — *Esquema Nacional de Seguridad* (Royal Decree 311/2022), Spain's national security framework.
- **NIS2** — the EU directive on network and information security.
- **CIS AWS Foundations Benchmark** — the international baseline.

So instead of an alert that says *"S3 bucket is public"*, Aegis Project produces:

> **Public S3 bucket detected** — `aegis-project-lab-data`
> Violates **ENS [op.exp.8]**, **NIS2 Art. 21**, **CIS AWS 2.1.5**. Auto-remediated in 4.2s.

Almost nobody does ENS mapping in a public portfolio project. For Spanish employers (and any company that handles EU public-sector data), this signals that you understand the regulatory reality they actually live in.

## Architecture

![Architecture diagram](docs/diagrams/architecture.png)
<!-- TODO: export your diagram to docs/diagrams/architecture.png (draw.io / Excalidraw) -->

| Layer | What it does | Key AWS services |
|-------|--------------|------------------|
| **Core** | Shared logging & event backbone | CloudTrail, EventBridge, SNS, S3, CloudWatch |
| **Scenarios** | Self-contained vulnerable setups | S3, IAM, EC2, VPC/Security Groups |
| **Detection** | Match malicious/risky events to rules | EventBridge rules -> Lambda |
| **Remediation** | Auto-fix the misconfiguration | Lambda + boto3 |
| **Engine** | Mapping, enrichment, alerting | Python (boto3) |
| **Dashboard** | Visualize attack -> detect -> respond | Streamlit / CloudWatch dashboard |

Each scenario is **fully modular** and follows the same internal pattern, so the range grows simply by adding folders.

## Repository layout

```
aegis-project/
├── infra/core/             # shared backbone: CloudTrail, EventBridge bus, SNS
├── infra/modules/          # reusable Terraform modules
├── scenarios/              # one folder per attack scenario (the heart of the range)
│   └── 01-public-s3-bucket/
│       ├── infra/          #   Terraform: the vulnerable resource
│       ├── attack/         #   Python: reproduce the exploit
│       ├── detection/      #   EventBridge rule + detection Lambda
│       ├── remediation/    #   Lambda that fixes it
│       ├── mapping.yaml    #   ENS / NIS2 / CIS mapping for this scenario
│       └── README.md       #   the scenario's story
├── engine/                 # shared Python: mapping, notifier, helpers
├── dashboard/              # visual layer for the demo
├── scripts/                # deploy / destroy / run-attack helpers
└── docs/                   # architecture, threat model, roadmap, compliance
```

## Scenario catalogue

| # | Scenario | Technique (MITRE ATT&CK) | Status |
|---|----------|--------------------------|--------|
| 01 | Public S3 bucket -> data exfiltration | T1530 Data from Cloud Storage | scaffolded |
| 02 | Over-privileged IAM -> privilege escalation | T1078 Valid Accounts | planned |
| 03 | Exposed SSH (0.0.0.0/0) -> brute force | T1110 Brute Force | planned |


## Quickstart

> Prerequisites: an **isolated AWS sandbox account**, [Terraform](https://terraform.io) >= 1.7, Python >= 3.12, AWS CLI configured.

```bash
git clone https://github.com/eloirey/aegis-project.git
cd aegis-project
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 1. Deploy the shared backbone (CloudTrail, EventBridge, SNS)
./scripts/deploy.sh core

# 2. Deploy a scenario (vulnerable infra + detection + remediation)
./scripts/deploy.sh scenarios/01-public-s3-bucket

# 3. Launch the attack and watch the auto-remediation kick in
./scripts/run-attack.sh 01-public-s3-bucket

# 4. Tear everything down (important for cost & safety!)
./scripts/destroy.sh
```

## Safety & cost

- **Run only in a dedicated sandbox AWS account.** Never in production.
- Every scenario is designed to fit inside the **AWS Free Tier** where possible; always `destroy` when done.
- Set up an **AWS Budget alert** before you start.
- The vulnerable resources are intentionally insecure — treat the whole account as untrusted while the lab is up.

## Roadmap

See [`docs/roadmap.md`](docs/roadmap.md) for the full phased plan. High level:

1. **MVP** — Core backbone + scenario 01 end to end (deploy -> attack -> detect -> remediate -> map).
2. **Breadth** — Add scenarios 02 and 03.
3. **Visualization** — Dashboard + a 2-3 min demo video.
4. **Polish** — CI/CD IaC scanning, tests, threat model, full ENS/NIS2 mapping docs.

## Tech stack

`Terraform` · `AWS (CloudTrail, EventBridge, Lambda, SNS, IAM, S3, EC2)` · `Python 3.12` · `boto3` · `Checkov / tfsec` · `GitHub Actions` · `Streamlit`

## Author

**Eloi Rey** — Computer Engineering student, focused on cloud security.
[LinkedIn](https://www.linkedin.com/in/eloi-rey-velardiez-93940338b) · [GitHub](https://github.com/eloirey)

---

<div align="center">
<sub>Aegis (Greek mythology): the shield of Zeus and Athena — a symbol of protection.</sub>
</div>
