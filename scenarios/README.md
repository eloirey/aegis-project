# Scenarios

Each scenario is a **self-contained incident** that plugs into the shared core backbone.
They all follow the exact same internal structure, so the range grows by **copying the
pattern**, not by rewriting plumbing.

## The pattern

```
NN-scenario-name/
├── infra/         # Terraform: creates the VULNERABLE resource
├── attack/        # Python: safely reproduces the exploit (the "red" step)
├── detection/     # EventBridge rule + Lambda: catches it (the "blue" step)
├── remediation/   # Lambda: auto-fixes it and alerts (the "auto" step)
├── mapping.yaml   # ENS / NIS2 / CIS controls for this finding
└── README.md      # the scenario told as a mini incident report
```

## How to add a new scenario
1. Copy `01-public-s3-bucket/` to `NN-your-scenario/`.
2. Edit `infra/` so it deploys the misconfiguration you want to study.
3. Write the `attack/` script that demonstrates the technique (keep it benign).
4. Identify the CloudTrail event(s) it generates, and write the `detection/` rule + Lambda.
5. Write the `remediation/` Lambda that fixes it.
6. Fill in `mapping.yaml` with the controls it violates.
7. Write the `README.md` as a short incident report: context → attack → detection →
   response → lessons.

## Scenario READMEs as incident reports
Treat each scenario README like a real (mini) incident write-up. That format reads as
professional and shows you can communicate security clearly:

- **Context** — what the misconfiguration is and why it's dangerous.
- **Attack** — the technique (with MITRE ATT&CK id) and how to run it.
- **Detection** — which event fires, the rule, the time-to-detect.
- **Response** — what the remediation does, the time-to-remediate.
- **Compliance** — controls violated (ENS / NIS2 / CIS).
- **Lessons** — how to prevent it in real life (e.g. SCPs, Block Public Access by default).
