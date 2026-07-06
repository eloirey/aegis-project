# dashboard/views/coverage.py
"""
Compliance coverage across the range: reads every scenario's mapping.yaml and shows what
each finding covers under ENS (RD 311/2022), NIS2 Art. 21 and CIS AWS Foundations v3.0.0.
Pure read of the repo's mapping files — no AWS connection.
"""
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st
import yaml

SCENARIOS_DIR = Path(__file__).resolve().parent.parent.parent / "scenarios"
FRAMEWORKS = [("ens", "ENS"), ("nis2", "NIS2"), ("cis_aws", "CIS AWS")]
FW_RANGE = ["#00D4FF", "#B98CFF", "#3DD68C"]  # ENS · NIS2 · CIS
SEV_CLASS = {"HIGH": "high", "MEDIUM": "med", "LOW": "low"}

CSS = """
<style>
html, body, [class*="css"] { font-family: 'Inter', -apple-system, 'Segoe UI', sans-serif; }
header[data-testid="stHeader"] { display: none; }
.block-container { padding-top: 2.2rem; max-width: 1180px; }

.brand { font-size: 12px; font-weight: 700; letter-spacing: 3px; color: #00D4FF;
  text-transform: uppercase; margin-bottom: 6px; }
.brand span { color: #5A6B82; }
.aegis-title { font-size: 30px; font-weight: 700; color: #E6EDF5; letter-spacing: -0.5px; }
.aegis-title span { color: #00D4FF; }
.aegis-sub { color: #8A97AB; font-size: 14px; margin: 2px 0 22px; }

.kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 30px; }
.kpi { background: #111A2B; border: 1px solid #1E2A3F; border-radius: 14px; padding: 16px 20px; }
.kpi .v { font-size: 30px; font-weight: 700; color: #E6EDF5; line-height: 1.1; }
.kpi .l { font-size: 11px; color: #8A97AB; text-transform: uppercase; letter-spacing: .6px; margin-top: 6px; }
.kpi.ens .v { color: #00D4FF; } .kpi.nis2 .v { color: #B98CFF; } .kpi.cis .v { color: #3DD68C; }

.section-h { font-size: 11px; text-transform: uppercase; letter-spacing: 1.3px; color: #8A97AB;
  font-weight: 700; margin: 28px 0 14px; }

.card { background: #111A2B; border: 1px solid #1E2A3F; border-left: 4px solid #4DA3FF;
  border-radius: 12px; padding: 20px 22px; margin-bottom: 14px; }
.card-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 14px; }
.fid { font-weight: 700; color: #E6EDF5; font-size: 16px; letter-spacing: .2px; }
.scn { color: #8A97AB; font-size: 12px; font-family: ui-monospace, monospace; margin-top: 3px; }
.sev { font-size: 11px; font-weight: 700; letter-spacing: .5px; padding: 4px 11px; border-radius: 20px; white-space: nowrap; }
.sev.high { color: #FF6B6B; background: rgba(255,107,107,.12); border: 1px solid rgba(255,107,107,.32); }
.sev.med { color: #FFB454; background: rgba(255,180,84,.12); border: 1px solid rgba(255,180,84,.32); }
.sev.low { color: #3DD68C; background: rgba(61,214,140,.12); border: 1px solid rgba(61,214,140,.32); }
.summary { color: #C7D2E0; font-size: 13.5px; line-height: 1.6; margin: 14px 0 8px; }
.mitre { color: #6E7C92; font-size: 12px; letter-spacing: .3px; margin-bottom: 4px; }

.fw-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 22px;
  border-top: 1px solid #1E2A3F; margin-top: 16px; padding-top: 16px; }
.fw-label { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .8px; margin-bottom: 11px; }
.fw-label.ens { color: #00D4FF; } .fw-label.nis2 { color: #B98CFF; } .fw-label.cis { color: #3DD68C; }
.ctrl { margin-bottom: 9px; }
.pill { font-family: ui-monospace, monospace; font-size: 11px; padding: 2px 7px; border-radius: 6px; }
.pill.ens { background: rgba(0,212,255,.12); color: #00D4FF; }
.pill.nis2 { background: rgba(185,140,255,.12); color: #B98CFF; }
.pill.cis { background: rgba(61,214,140,.12); color: #3DD68C; }
.ctrl-name { color: #8A97AB; font-size: 12.5px; line-height: 1.4; display: block; margin-top: 4px; }

.foot { border-top: 1px solid #1E2A3F; margin-top: 16px; padding-top: 13px;
  color: #8A97AB; font-size: 12.5px; line-height: 1.9; }
.foot-k { color: #00D4FF; font-weight: 700; text-transform: uppercase; font-size: 10px;
  letter-spacing: .8px; margin-right: 9px; }
.foot code { background: rgba(255,255,255,.05); padding: 1px 6px; border-radius: 5px; color: #C7D2E0; font-size: 12px; }

.aegis-footer { margin: 40px 0 10px; padding-top: 18px; border-top: 1px solid #1E2A3F;
  display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;
  color: #5A6B82; font-size: 12px; }
.aegis-footer a { color: #8A97AB; text-decoration: none; }
.aegis-footer a:hover { color: #00D4FF; }
.aegis-footer .links { display: flex; gap: 16px; }
</style>
"""


@st.cache_data
def load_scenarios():
    return [
        yaml.safe_load(p.read_text(encoding="utf-8"))
        for p in sorted(SCENARIOS_DIR.glob("*/mapping.yaml"))
    ]


def control_ids(scenario, framework):
    return [c["id"] for c in scenario.get("compliance", {}).get(framework, [])]


def triggers(detection):
    # 01 uses a single trigger_event, 02/03 use a trigger_events list.
    if detection.get("trigger_events"):
        return ", ".join(detection["trigger_events"])
    return detection.get("trigger_event", "n/a")


def chips(scenario, framework, css):
    out = ""
    for c in scenario.get("compliance", {}).get(framework, []):
        out += (
            f'<div class="ctrl"><span class="pill {css}">{c["id"]}</span>'
            f'<span class="ctrl-name">{c["name"]}</span></div>'
        )
    return out or '<span class="ctrl-name">—</span>'


st.markdown(CSS, unsafe_allow_html=True)
st.markdown(
    '<div class="brand">Aegis <span>Project</span></div>'
    '<div class="aegis-title">Compliance <span>Coverage</span></div>'
    '<div class="aegis-sub">Every finding mapped to ENS (RD 311/2022), NIS2 Art. 21 '
    "and CIS AWS Foundations v3.0.0</div>",
    unsafe_allow_html=True,
)

scenarios = load_scenarios()
if not scenarios:
    st.warning("No mapping.yaml files found under scenarios/.")
    st.stop()

st.sidebar.markdown("### Filters")
names = [s["scenario"] for s in scenarios]
chosen = st.sidebar.multiselect("Scenarios", names, default=names)
view = [s for s in scenarios if s["scenario"] in chosen]
if not view:
    st.info("Select at least one scenario.")
    st.stop()

# --- KPIs: the mapping is the differentiator, so lead with control counts ---
unique = {fw: {c for s in view for c in control_ids(s, fw)} for fw, _ in FRAMEWORKS}
st.markdown(
    '<div class="kpi-grid">'
    f'<div class="kpi"><div class="v">{len(view)}</div><div class="l">Scenarios</div></div>'
    f'<div class="kpi ens"><div class="v">{len(unique["ens"])}</div><div class="l">ENS controls</div></div>'
    f'<div class="kpi nis2"><div class="v">{len(unique["nis2"])}</div><div class="l">NIS2 controls</div></div>'
    f'<div class="kpi cis"><div class="v">{len(unique["cis_aws"])}</div><div class="l">CIS AWS controls</div></div>'
    "</div>",
    unsafe_allow_html=True,
)

# --- coverage chart ---
st.markdown('<div class="section-h">Controls mapped per scenario</div>', unsafe_allow_html=True)
rows = [
    {"scenario": s["scenario"].split("-", 1)[-1], "framework": label, "controls": len(control_ids(s, fw))}
    for s in view
    for fw, label in FRAMEWORKS
]
chart = (
    alt.Chart(pd.DataFrame(rows))
    .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
    .encode(
        x=alt.X("scenario:N", title=None, axis=alt.Axis(labelAngle=0, labelPadding=8)),
        xOffset="framework:N",
        y=alt.Y("controls:Q", title="Controls", axis=alt.Axis(tickMinStep=1)),
        color=alt.Color(
            "framework:N",
            scale=alt.Scale(domain=["ENS", "NIS2", "CIS AWS"], range=FW_RANGE),
            legend=alt.Legend(orient="top", title=None, symbolType="circle"),
        ),
        tooltip=["scenario", "framework", "controls"],
    )
    .properties(height=270)
    .configure(background="transparent")
    .configure_view(strokeWidth=0)
    .configure_axis(grid=False, labelColor="#8A97AB", titleColor="#6E7C92", domainColor="#1E2A3F", tickColor="#1E2A3F")
    .configure_legend(labelColor="#C7D2E0")
)
st.altair_chart(chart, use_container_width=True)

# --- per-scenario detail ---
st.markdown('<div class="section-h">Scenarios</div>', unsafe_allow_html=True)
for s in view:
    sev = s.get("severity", "n/a")
    summary = " ".join(s.get("summary", "").split())
    mitre = ", ".join(s.get("mitre_attack", [])) or "n/a"
    det, rem = s.get("detection", {}), s.get("remediation", {})
    resp = ", ".join(rem.get("actions", [])) or "n/a"
    st.markdown(
        '<div class="card">'
        '<div class="card-head"><div>'
        f'<div class="fid">{s["finding_id"]}</div>'
        f'<div class="scn">{s["scenario"]}</div></div>'
        f'<span class="sev {SEV_CLASS.get(sev, "high")}">{sev}</span></div>'
        f'<div class="summary">{summary}</div>'
        f'<div class="mitre">MITRE ATT&amp;CK · {mitre}</div>'
        '<div class="fw-grid">'
        f'<div><div class="fw-label ens">ENS</div>{chips(s, "ens", "ens")}</div>'
        f'<div><div class="fw-label nis2">NIS2</div>{chips(s, "nis2", "nis2")}</div>'
        f'<div><div class="fw-label cis">CIS AWS</div>{chips(s, "cis_aws", "cis")}</div>'
        "</div>"
        '<div class="foot">'
        f'<div><span class="foot-k">Detect</span>{triggers(det)} &rarr; '
        f'<code>{det.get("eventbridge_rule", "n/a")}</code></div>'
        f'<div><span class="foot-k">Respond</span>{resp}</div>'
        "</div></div>",
        unsafe_allow_html=True,
    )

st.markdown(
    '<div class="aegis-footer">'
    '<div>Built by Eloi Rey · Aegis Project</div>'
    '<div class="links">'
    '<a href="https://github.com/eloirey/aegis-project" target="_blank">GitHub</a>'
    '<a href="https://www.linkedin.com/in/eloi-rey/" target="_blank">LinkedIn</a>'
    '<a href="https://eloirey.github.io" target="_blank">Portfolio</a>'
    '</div></div>',
    unsafe_allow_html=True,
)