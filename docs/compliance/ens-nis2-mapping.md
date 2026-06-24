# 🇪🇸🇪🇺 Compliance mapping: ENS · NIS2 · CIS

This is what sets Aegis Project apart. Every finding is translated from "a misconfiguration"
into "a control violation in a framework a company is legally accountable to."

> ⚠️ **Verify before you publish.** Frameworks get updated. Before claiming a specific
> control reference, check the current official text:
> - **ENS** — *Esquema Nacional de Seguridad*, currently Royal Decree 311/2022 (CCN-CERT
>   publishes the control catalogue and guides, e.g. CCN-STIC-800 series).
> - **NIS2** — Directive (EU) 2022/2555 and its national transposition.
> - **CIS** — CIS AWS Foundations Benchmark (note the version number you used).
>
> The references below are **illustrative starting points**, not legal advice. Confirm
> each mapping against the source and cite the version.

## How the mapping works

Each scenario ships a `mapping.yaml`. The engine loads it and attaches the controls to
every finding it produces. Example shape:

```yaml
# scenarios/01-public-s3-bucket/mapping.yaml
finding_id: PUBLIC_S3_BUCKET
title: Publicly accessible S3 bucket
severity: HIGH
mitre_attack: ["T1530"]
controls:
  ens:
    - id: "op.exp.8"          # verify against RD 311/2022 control catalogue
      name: "Registro de la actividad de los usuarios"
    - id: "mp.info.*"         # protección de la información
  nis2:
    - article: "Art. 21"
      topic: "Cybersecurity risk-management measures"
  cis_aws:
    - id: "2.1.x"             # confirm exact control & benchmark version
      name: "Ensure S3 buckets are not publicly accessible"
remediation: "Enable S3 Block Public Access and remove public ACL/policy."
```

## Mapping table (work in progress — fill as you build)

| Finding | ENS (RD 311/2022) | NIS2 | CIS AWS | Status |
|---------|-------------------|------|---------|--------|
| Public S3 bucket | `mp.info` / `op.exp` (verify) | Art. 21 | 2.1.x (verify) | 🏗️ |
| Over-privileged IAM | `op.acc` (control de acceso) | Art. 21 | 1.x (verify) | 📋 |
| Exposed SSH 0.0.0.0/0 | `mp.com` (protección comunicaciones) | Art. 21 | 5.x (verify) | 📋 |

## Why this matters for employers
- Spanish public administrations and their suppliers **must** comply with ENS.
- NIS2 expands mandatory cybersecurity obligations across many EU sectors.
- Showing you can connect a technical finding to a regulatory control is exactly the
  bridge between "security engineer" and "security that the business understands."
