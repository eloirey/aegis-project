# 🏗️ Architecture

## The detection loop

Aegis Project is built around a single repeatable loop. Every scenario plugs into the same
shared backbone, so adding a new attack only means adding a new folder.

```
                         ┌─────────────────────────────────────────────┐
                         │                  CORE BACKBONE               │
                         │                                              │
   attacker / script     │   CloudTrail ──▶ EventBridge bus ──▶ rules   │
        │                │       ▲                              │       │
        ▼                │       │                              ▼       │
  ┌────────────┐  API    │   AWS API calls            ┌──────────────┐  │
  │ vulnerable │ ──────────────────────────────────▶ │  detection   │  │
  │  resource  │         │                            │   Lambda     │  │
  └────────────┘         │                            └──────┬───────┘  │
        ▲                │                                   │          │
        │ auto-fix       │                                   ▼          │
  ┌─────┴──────┐         │   ┌───────────────┐      ┌──────────────┐    │
  │ remediation│ ◀───────────│  mapping +    │ ◀────│   finding    │    │
  │   Lambda   │         │   │  enrichment   │      │  (event)     │    │
  └────────────┘         │   └───────┬───────┘      └──────────────┘    │
                         │           │ ENS / NIS2 / CIS                 │
                         │           ▼                                  │
                         │      SNS topic ──▶ email / Slack / dashboard │
                         └─────────────────────────────────────────────┘
```

## Components

### Core (`infra/core`)
The shared, always-on backbone every scenario depends on:
- **CloudTrail** — records every API call in the account. This is your source of truth.
- **EventBridge bus + rules** — routes interesting CloudTrail events to detection Lambdas.
- **SNS topic** — central alerting channel (email now, Slack/dashboard later).
- **Log bucket + CloudWatch** — storage and observability.

### Scenario (`scenarios/NN-name/`)
A self-contained unit with five parts that always follow the same shape:
- `infra/` — Terraform that creates the **vulnerable** resource.
- `attack/` — a Python script that **reproduces the exploit** safely.
- `detection/` — the EventBridge rule + Lambda that **catches** it.
- `remediation/` — the Lambda that **fixes** it and emits an alert.
- `mapping.yaml` — the ENS / NIS2 / CIS controls this scenario relates to.

### Engine (`engine/`)
Shared Python used by the Lambdas:
- `mapping/` — loads each scenario's `mapping.yaml` and enriches a finding with controls.
- `notifier/` — formats and publishes alerts to SNS.
- `detection/`, `remediation/` — shared helpers so scenarios don't repeat boilerplate.

## Design principles
1. **Reproducible** — everything is Terraform; `apply` to build, `destroy` to remove.
2. **Modular** — scenarios are independent; the range grows by addition, not rewriting.
3. **Observable** — every step (attack, detect, remediate) leaves a visible trace.
4. **Compliance-aware** — findings are never raw; they always carry their control mapping.
5. **Cheap & safe** — Free Tier friendly, sandbox-only, always tear-down-able.

## Key technical decisions (write these up — interviewers love the "why")
- **Why EventBridge over polling?** Event-driven detection is near real-time and cheaper.
- **Why Lambda for remediation?** Serverless = no infra to babysit, scales to zero.
- **Why CloudTrail as the source?** It's the authoritative record of every API action.
- **Why a mapping layer?** It turns raw security events into business/compliance language.
