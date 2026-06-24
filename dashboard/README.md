# Dashboard  *(Phase 4)*

The visual layer that makes the demo pop. Fastest path: a **Streamlit** app that reads
findings (from SNS history, a DynamoDB table, or CloudWatch Logs) and shows, per scenario:

- timeline: attack launched → detected → remediated
- time-to-detect and time-to-remediate metrics
- the compliance controls each finding hit (ENS / NIS2 / CIS)
- a live "lab status" panel

Run locally:
```bash
streamlit run dashboard/app.py
```

`app.py` is intentionally not scaffolded yet — design it once scenario 01 emits real
findings so the data model is driven by reality, not guesses.
