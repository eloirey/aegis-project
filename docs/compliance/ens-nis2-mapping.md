# 🇪🇸 🇪🇺 Compliance mapping — ENS · NIS2 · CIS

This is what sets Aegis apart. Every finding is translated from *"a misconfiguration"* into *"a control violation in a framework an organisation is legally accountable to."* Each scenario ships a `mapping.yaml`, the engine loads it, and every finding it produces carries the exact controls it breached — along with a short rationale for **why** that control applies.

**Framework versions** (pinned on purpose — control IDs shift between releases, so an unversioned mapping would rot silently):

- **ENS** — *Esquema Nacional de Seguridad*, Royal Decree **311/2022** (Art. 20 + Anexo II).
- **NIS2** — Directive **(EU) 2022/2555**, Art. 21(2).
- **CIS** — CIS **AWS Foundations Benchmark v3.0.0**.

> **A note on rigour.** The mappings below are my own reasoned interpretation, cross-referenced against the official framework texts and pinned to the versions above. Frameworks get updated; anyone reusing this should re-confirm each control against the current source. Each mapping in the `mapping.yaml` files includes a `rationale` explaining the connection, so the reasoning is auditable rather than asserted.

---

## How the mapping works

Each scenario carries a `mapping.yaml`. The engine attaches its controls to every finding, so an alert isn't *"S3 bucket is public"* but *"this violates ENS op.exp.2, NIS2 Art. 21(2)(i), CIS AWS 2.1.4 — and here's why."* The real shape (from `scenarios/03-exposed-ssh/mapping.yaml`):

```yaml
scenario: 03-exposed-ssh
finding_id: EXPOSED_SSH
severity: HIGH
mitre_attack: [T1133]
detection:
  log_source: CloudTrail
  trigger_events: [AuthorizeSecurityGroupIngress]
  eventbridge_rule: aegis-project-03-exposed-ssh
remediation:
  actions: [ec2:RevokeSecurityGroupIngress]   # removes only the offending rule
  outcome: the exposed rule is revoked; the rest of the security group is left intact
compliance:
  ens:
    - id: mp.com.1
      name: Perímetro seguro
      rationale: Opening SSH to 0.0.0.0/0 breaks the secure perimeter; remediation restores it.
    # …
  nis2:
    - id: Art. 21(2)(i)
      name: Access control policies and asset management
      rationale: Restricting which networks can reach admin ports is an access control the remediation re-enforces.
    # …
  cis_aws:
    - id: "5.2"
      name: Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports
      rationale: The attack opens tcp/22 to 0.0.0.0/0 — exactly what this control forbids.
    # …
```

Every control entry pairs an official **`id`/`name`** with a **`rationale`**, so the mapping can be audited, not just trusted.

---

## Coverage summary

All three scenarios are implemented and verified against real AWS. Controls below are the exact IDs each finding maps to.

### 01 · Public S3 bucket — `PUBLIC_S3_BUCKET` · `HIGH` · MITRE T1530

| Framework | Controls |
|-----------|----------|
| **ENS** (RD 311/2022) | `op.acc.2` Requisitos de acceso · `op.exp.2` Configuración de seguridad · `op.exp.8` Registro de la actividad · `op.mon.1` Detección de intrusión |
| **NIS2** (Art. 21(2)) | `(b)` Incident handling · `(e)` Vulnerability handling · `(i)` Access control & asset management |
| **CIS AWS** (v3.0.0) | `2.1.4` Block public access (bucket) · `2.1.1` Account-level Block Public Access |

### 02 · Over-privileged IAM — `PRIVILEGED_IAM` · `HIGH` · MITRE T1078, T1098

| Framework | Controls |
|-----------|----------|
| **ENS** (RD 311/2022) | `art.20` Mínimo privilegio · `op.acc.4` Gestión de derechos de acceso · `op.acc.3` Segregación de funciones · `op.exp.8` Registro de la actividad · `op.mon.1` Detección de intrusión |
| **NIS2** (Art. 21(2)) | `(i)` Access control & asset management · `(b)` Incident handling · `(e)` Vulnerability handling |
| **CIS AWS** (v3.0.0) | `1.16` No full `*:*` admin policies attached · `1.15` Permissions only through groups |

### 03 · Exposed SSH `0.0.0.0/0` — `EXPOSED_SSH` · `HIGH` · MITRE T1133

| Framework | Controls |
|-----------|----------|
| **ENS** (RD 311/2022) | `mp.com.1` Perímetro seguro · `op.exp.2` Configuración de seguridad · `op.exp.8` Registro de la actividad · `op.mon.1` Detección de intrusión |
| **NIS2** (Art. 21(2)) | `(i)` Access control & asset management · `(e)` Vulnerability handling · `(b)` Incident handling |
| **CIS AWS** (v3.0.0) | `5.2` No ingress from 0.0.0.0/0 to admin ports · `5.3` No ingress from ::/0 to admin ports |

---

## Why this matters for employers

- **Spanish public administrations and their suppliers must comply with ENS.** Very few portfolio projects touch it at all.
- **NIS2 expands mandatory cybersecurity obligations** across many EU sectors, so the ability to tie a technical finding to a specific Art. 21(2) duty is directly relevant.
- Connecting a technical finding to a regulatory control is exactly the bridge between *"a security engineer"* and *"security the business is accountable for."*
