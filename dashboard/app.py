"""
Aegis Project - compliance coverage dashboard.

Reads every scenario's mapping.yaml and shows what the range covers across ENS,
NIS2 and CIS AWS. Pure read of the repo's mapping files - no AWS connection, so it
runs anywhere with `streamlit run dashboard/app.py`.
"""
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st
import yaml

SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "scenarios"
FRAMEWORKS = [("ens", "ENS", "ens"), ("nis2", "NIS2", "nis2"), ("cis_aws", "CIS AWS", "cis")]
FW_RANGE = ["#00D4FF", "#B98CFF", "#5CE1A6"]
SEV_BADGE = {"HIGH": "badge-high", "MEDIUM": "badge-med", "LOW": "badge-low"}

STYLE = """
<style>
:root{--cyan:#00D4FF;--panel:#10182A;--line:#1E2A40;--text:#E6EDF3;--muted:#8B98AD;}
header[data-testid="stHeader"]{display:none;}
#MainMenu,footer{visibility:hidden;}
.block-container{padding-top:1.4rem;max-width:1180px;}
.hero{border-left:3px solid var(--cyan);padding:.1rem 0 .1rem 1.1rem;margin-bottom:1.7rem;}
.hero-title{font-size:1.85rem;font-weight:800;letter-spacing:.2em;color:var(--text);}
.hero-sub{font-size:1.02rem;color:var(--cyan);font-weight:600;margin-top:-1px;}
.hero-tag{color:var(--muted);font-size:.88rem;margin-top:.45rem;}
.kpi-row{display:flex;gap:13px;margin:0 0 .6rem;}
.kpi{flex:1;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:15px 18px;}
.kpi-val{font-size:1.85rem;font-weight:700;color:var(--cyan);line-height:1;}
.kpi-label{color:var(--muted);font-size:.72rem;margin-top:.5rem;text-transform:uppercase;letter-spacing:.07em;}
.section-h{font-size:.76rem;text-transform:uppercase;letter-spacing:.13em;color:var(--muted);
  margin:1.9rem 0 .8rem;font-weight:700;}
.scn-card{background:var(--panel);border:1px solid var(--line);border-radius:14px;
  padding:20px 22px;margin-bottom:15px;}
.scn-head{display:flex;justify-content:space-between;align-items:flex-start;}
.scn-id{font-weight:700;color:var(--text);font-size:1.04rem;letter-spacing:.02em;}
.scn-name{color:var(--muted);font-size:.8rem;margin-top:2px;}
.badge{font-size:.68rem;font-weight:700;padding:3px 11px;border-radius:20px;letter-spacing:.05em;}
.badge-high{background:rgba(251,113,133,.14);color:#FB7185;border:1px solid rgba(251,113,133,.32);}
.badge-med{background:rgba(255,200,87,.14);color:#FFC857;border:1px solid rgba(255,200,87,.32);}
.badge-low{background:rgba(92,225,166,.14);color:#5CE1A6;border:1px solid rgba(92,225,166,.32);}
.scn-summary{color:#C7D2E0;font-size:.89rem;line-height:1.55;margin:.75rem 0 .55rem;}
.scn-mitre{color:var(--muted);font-size:.76rem;letter-spacing:.04em;margin-bottom:1rem;}
.fw-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:20px;
  border-top:1px solid var(--line);padding-top:1.05rem;}
.fw-label{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:.65rem;}
.fw-label.ens{color:#00D4FF;}.fw-label.nis2{color:#B98CFF;}.fw-label.cis{color:#5CE1A6;}
.ctrl{display:flex;align-items:baseline;gap:8px;margin-bottom:7px;}
.pill{font-family:ui-monospace,SFMono-Regular,monospace;font-size:.71rem;padding:1px 7px;
  border-radius:6px;white-space:nowrap;}
.pill.ens{background:rgba(0,212,255,.12);color:#00D4FF;}
.pill.nis2{background:rgba(185,140,255,.12);color:#B98CFF;}
.pill.cis{background:rgba(92,225,166,.12);color:#5CE1A6;}
.ctrl-name{color:var(--muted);font-size:.79rem;line-height:1.3;}
.scn-foot{border-top:1px solid var(--line);margin-top:1.05rem;padding-top:.9rem;
  color:var(--muted);font-size:.79rem;line-height:1.85;}
.foot-k{color:var(--cyan);font-weight:700;text-transform:uppercase;font-size:.66rem;
  letter-spacing:.08em;margin-right:9px;}
.scn-foot code{background:rgba(255,255,255,.05);padding:1px 6px;border-radius:5px;
  color:#C7D2E0;font-size:.75rem;}
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
    return out or '<span class="ctrl-name">-</span>'


st.set_page_config(page_title="Aegis - Compliance Coverage", layout="wide")
st.markdown(STYLE, unsafe_allow_html=True)

scenarios = load_scenarios()

st.markdown(
    '<div class="hero">'
    '<div class="hero-title">AEGIS PROJECT</div>'
    '<div class="hero-sub">Compliance Coverage</div>'
    '<div class="hero-tag">Self-healing AWS security range &mdash; every finding mapped to '
    'ENS (RD 311/2022), NIS2 Art. 21 and CIS AWS Foundations v3.0.0</div>'
    "</div>",
    unsafe_allow_html=True,
)

if not scenarios:
    st.warning("No mapping.yaml files found under scenarios/. Run this from the repo root.")
    st.stop()

st.sidebar.markdown("### Filters")
names = [s["scenario"] for s in scenarios]
chosen = st.sidebar.multiselect("Scenarios", names, default=names)
view = [s for s in scenarios if s["scenario"] in chosen]
if not view:
    st.info("Select at least one scenario.")
    st.stop()

# --- KPIs ---
unique = {fw: {c for s in view for c in control_ids(s, fw)} for fw, _, _ in FRAMEWORKS}
high = sum(1 for s in view if s.get("severity") == "HIGH")
kpis = [
    ("Scenarios", len(view)),
    ("High severity", high),
    ("ENS controls", len(unique["ens"])),
    ("NIS2 controls", len(unique["nis2"])),
    ("CIS AWS controls", len(unique["cis_aws"])),
]
st.markdown(
    '<div class="kpi-row">'
    + "".join(
        f'<div class="kpi"><div class="kpi-val">{v}</div>'
        f'<div class="kpi-label">{label}</div></div>'
        for label, v in kpis
    )
    + "</div>",
    unsafe_allow_html=True,
)

# --- coverage chart ---
st.markdown('<div class="section-h">Controls mapped per scenario</div>', unsafe_allow_html=True)
rows = []
for s in view:
    short = s["scenario"].split("-", 1)[-1]
    for fw, label, _ in FRAMEWORKS:
        rows.append({"scenario": short, "framework": label, "controls": len(control_ids(s, fw))})
long_df = pd.DataFrame(rows)

chart = (
    alt.Chart(long_df)
    .mark_bar(cornerRadiusTopLeft=3, cornerRadiusTopRight=3)
    .encode(
        x=alt.X("scenario:N", title=None, axis=alt.Axis(labelAngle=0)),
        xOffset="framework:N",
        y=alt.Y("controls:Q", title="Controls", axis=alt.Axis(tickMinStep=1)),
        color=alt.Color(
            "framework:N",
            scale=alt.Scale(domain=["ENS", "NIS2", "CIS AWS"], range=FW_RANGE),
            legend=alt.Legend(orient="top", title=None),
        ),
        tooltip=["scenario", "framework", "controls"],
    )
    .properties(height=260)
    .configure_view(strokeWidth=0)
    .configure_axis(grid=False, labelColor="#8B98AD", titleColor="#8B98AD", domainColor="#1E2A40")
    .configure_legend(labelColor="#C7D2E0")
)
st.altair_chart(chart, use_container_width=True)

# --- per-scenario detail ---
st.markdown('<div class="section-h">Scenarios</div>', unsafe_allow_html=True)
for s in view:
    sev = s.get("severity", "n/a")
    badge = SEV_BADGE.get(sev, "badge-high")
    summary = " ".join(s.get("summary", "").split())
    mitre = ", ".join(s.get("mitre_attack", [])) or "n/a"
    det, rem = s.get("detection", {}), s.get("remediation", {})
    resp = ", ".join(rem.get("actions", [])) or "n/a"
    card = (
        '<div class="scn-card">'
        '<div class="scn-head"><div>'
        f'<div class="scn-id">{s["finding_id"]}</div>'
        f'<div class="scn-name">{s["scenario"]}</div>'
        f'</div><span class="badge {badge}">{sev}</span></div>'
        f'<div class="scn-summary">{summary}</div>'
        f'<div class="scn-mitre">MITRE ATT&amp;CK&nbsp;&middot;&nbsp;{mitre}</div>'
        '<div class="fw-grid">'
        f'<div><div class="fw-label ens">ENS</div>{chips(s, "ens", "ens")}</div>'
        f'<div><div class="fw-label nis2">NIS2</div>{chips(s, "nis2", "nis2")}</div>'
        f'<div><div class="fw-label cis">CIS AWS</div>{chips(s, "cis_aws", "cis")}</div>'
        "</div>"
        '<div class="scn-foot">'
        f'<div><span class="foot-k">Detect</span>{triggers(det)} &rarr; '
        f'<code>{det.get("eventbridge_rule", "n/a")}</code></div>'
        f'<div><span class="foot-k">Respond</span>{resp}</div>'
        "</div></div>"
    )
    st.markdown(card, unsafe_allow_html=True)