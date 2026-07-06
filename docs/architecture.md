# Architecture

Aegis is built around a single repeatable loop. Every scenario plugs into the same shared backbone, so adding a new attack means adding a folder — not rewriting anything.

![Aegis architecture](diagrams/architecture.png)

## The self-healing loop

1. **Deploy** — Terraform stands up a deliberately vulnerable resource (the scenario infra).
2. **Attack** — a Python/boto3 script reproduces the exploit safely, making a real AWS API call.
3. **Detect** — CloudTrail records the call; an EventBridge rule matches it and invokes the detection Lambda, which inspects the event **by its content** (not by who made it) and raises a structured finding.
4. **Enrich & alert** — the finding is enriched with the ENS / NIS2 / CIS controls it violates, recorded in DynamoDB, and published to SNS. An enriched email alert reaches the subscriber.
5. **Respond** — a second Lambda auto-fixes the resource **surgically and reversibly** (block public access, quarantine the identity, revoke the offending ingress rule) and updates the finding's lifecycle to *remediated*.

Detection and remediation are decoupled through SNS, and the whole cycle runs in seconds — fully serverless, entirely defined in Terraform.

## Components

### Core (`infra/core`) — built
The shared, always-on backbone every scenario depends on:

- **CloudTrail** — multi-region trail that records every API call in the account. Source of truth.
- **EventBridge** — the default event bus carries CloudTrail events; each scenario adds its own rule.
- **SNS** — `aegis-project-alerts` is the alerting channel that delivers the enriched email.
- **DynamoDB** — `aegis-project-findings` stores the finding lifecycle (`detected` → `remediated`), giving the live dashboard a real-time, region-aware view.
- **S3 + CloudWatch** — log storage and Lambda observability.

The core is designed to stay up at effectively zero cost; only scenario infrastructure needs tearing down after a session.

### Scenarios (`scenarios/NN-name/`) — 01, 02 & 03 built and verified
A self-contained unit with the same five parts every time:

- `infra/` — Terraform that creates the vulnerable resource.
- `attack/` — a Python script that reproduces the exploit safely.
- `detection/` — the EventBridge rule + Lambda that catches it (by content), which enriches the finding, records it in DynamoDB and publishes to the scenario's SNS topic.
- `remediation/` — the Lambda (subscribed to that topic) that fixes it reversibly and flips the finding to *remediated*.
- `mapping.yaml` — the ENS / NIS2 / CIS controls this scenario relates to, each with a rationale.

**Region note:** regional scenarios live in `eu-west-1`. IAM is a global service, so its CloudTrail events are delivered to EventBridge only in `us-east-1` — scenario 02's rule and Lambdas run there, while still writing findings **cross-region** to the DynamoDB table in `eu-west-1`.

### Engine (`engine/`) — implemented, tested, and wired into the live path
A shared Python package that removes boilerplate from the Lambdas and carries the signature feature:

- **mapper** — loads a scenario's `mapping.yaml` and enriches a raw event into a finding with its severity, MITRE techniques and ENS / NIS2 / CIS controls. This is what turns *"a misconfiguration"* into *"a control violation."*
- **notifier** — formats the enriched finding into a readable alert and publishes it to the alerts topic.
- **store** (`engine/store/`) — records the lifecycle in DynamoDB: `record_detection()` writes the finding as `detected`; `record_remediation()` flips it to `remediated`. Region-aware, so scenario 02 writes cross-region from `us-east-1`.

The engine is covered by a **pytest** suite (using `moto` to mock AWS) and is **wired into all three detection Lambdas at runtime** — each scenario injects its `mapping.yaml` controls as Lambda configuration, and the enriched, compliance-aware alert reaches the `aegis-project-alerts` email subscription in production. (Verified end to end against real AWS, including the cross-region case.)

### Dashboards (`dashboard/`)
A multipage Streamlit app:

- **Live Findings** — reads DynamoDB in real time and shows each finding move from *detected* (amber) to *remediated* (green), with a time-to-remediate metric and the compliance controls per finding.
- **Compliance Coverage** — reads every scenario's `mapping.yaml` and visualises how many ENS / NIS2 / CIS controls the range exercises.

## Design principles

- **Reproducible** — everything is Terraform; apply to build, destroy to remove.
- **Modular** — scenarios are independent; the range grows by addition, not rewriting.
- **Observable** — every step (attack, detect, remediate) leaves a visible trace, in the alert and in the live dashboard.
- **Compliance-aware** — every finding maps to the controls it violates, at runtime.
- **Reversible** — remediation is surgical: it neutralises the threat without destroying legitimate configuration.
- **Cheap & safe** — Free Tier friendly, sandbox-only, always tear-down-able.

## Key technical decisions (the "why")

- **Why EventBridge over polling?** Event-driven detection is near real-time and cheaper.
- **Why detect by content, not by actor?** A finding should fire on *what* changed (SSH open to the world) regardless of *who* did it — that's what makes detection robust.
- **Why Lambda for remediation?** Serverless — no infrastructure to babysit, scales to zero.
- **Why reversible remediation?** In real operations you contain a threat without breaking legitimate access; e.g. IAM quarantine layers an explicit-deny instead of detaching policies, and the SSH fix revokes only the offending rule.
- **Why CloudTrail as the source?** It's the authoritative record of every API action.
- **Why SNS between detect and respond?** Decoupling lets one finding fan out to multiple responders (remediation, email, and — via DynamoDB — the dashboard) without touching the detector.
- **Why a mapping layer?** It turns raw security events into compliance language — the differentiator — and it runs live, not just in tests.
