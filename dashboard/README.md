# Dashboard

A multipage **Streamlit** app that visualises the range. Launch it with:

```bash
streamlit run dashboard/app.py
```

## Pages

### Live Findings (`views/live_findings.py`)
The centrepiece of the demo. Reads the DynamoDB lifecycle table in real time (auto-refreshing
via `st.fragment`) and shows each finding the moment it's detected — in amber — flipping to
remediated in green seconds later. Includes KPIs (total findings, active threats,
auto-remediated, average response time), a detected → remediated timeline per finding, and the
ENS / NIS2 / CIS controls each one hit.

### Compliance Coverage (`views/coverage.py`)
Reads every scenario's `mapping.yaml` (no AWS connection needed) and shows how many controls the
range exercises under ENS (RD 311/2022), NIS2 Art. 21 and CIS AWS Foundations v3.0.0 — with an
Altair breakdown per framework and a per-scenario detail card.

## Theme

The shared dark navy/cyan theme lives in `.streamlit/config.toml` at the repo root.