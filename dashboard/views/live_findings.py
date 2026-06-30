# dashboard/views/live_findings.py
"""
Live view of the self-healing pipeline: each finding shows up the moment detection records
it and flips to remediated seconds later, read straight from the DynamoDB lifecycle table.
"""
import os
from datetime import datetime

import boto3
import streamlit as st

TABLE = os.environ.get("FINDINGS_TABLE", "aegis-project-findings")
REGION = os.environ.get("FINDINGS_TABLE_REGION", "eu-west-1")
REFRESH_SECONDS = 2

# The two states the whole product is about, plus severity scale.
SEVERITY_COLOR = {"CRITICAL": "#FF4D4D", "HIGH": "#FF6B6B", "MEDIUM": "#FFB454", "LOW": "#4DA3FF"}
FINDING_LABEL = {
    "PUBLIC_S3_BUCKET": "Public S3 Bucket",
    "PRIVILEGED_IAM": "Over-Privileged IAM",
    "EXPOSED_SSH": "Exposed SSH",
}

CSS = """
<style>
html, body, [class*="css"] { font-family: 'Inter', -apple-system, 'Segoe UI', sans-serif; }
.block-container { padding-top: 2.2rem; max-width: 1180px; }
.brand { font-size: 12px; font-weight: 700; letter-spacing: 3px; color: #00D4FF;
  text-transform: uppercase; margin-bottom: 6px; }
.brand span { color: #5A6B82; }
.aegis-title { font-size: 30px; font-weight: 700; color: #E6EDF5; letter-spacing: -0.5px; }
.aegis-title span { color: #00D4FF; }
.aegis-sub { color: #8A97AB; font-size: 14px; margin: 2px 0 16px; }
.live-bar { display: flex; align-items: center; gap: 9px; color: #8A97AB; font-size: 13px; margin-bottom: 22px; }
.live-dot { width: 9px; height: 9px; border-radius: 50%; background: #3DD68C; animation: ping 1.6s infinite; }
@keyframes ping { 0% { box-shadow: 0 0 0 0 rgba(61,214,140,.5); } 70% { box-shadow: 0 0 0 7px rgba(61,214,140,0); } 100% { box-shadow: 0 0 0 0 rgba(61,214,140,0); } }
.kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 28px; }
.kpi { background: #111A2B; border: 1px solid #1E2A3F; border-radius: 14px; padding: 16px 20px; }
.kpi .v { font-size: 30px; font-weight: 700; color: #E6EDF5; line-height: 1.1; }
.kpi .l { font-size: 11px; color: #8A97AB; text-transform: uppercase; letter-spacing: .6px; margin-top: 6px; }
.kpi.cyan .v { color: #00D4FF; }
.kpi.amber .v { color: #FFB454; }
.kpi.green .v { color: #3DD68C; }
.feed { display: flex; flex-direction: column; gap: 12px; }
.card { display: flex; align-items: stretch; justify-content: space-between; gap: 16px; background: #111A2B; border: 1px solid #1E2A3F; border-left: 4px solid #4DA3FF; border-radius: 12px; padding: 14px 18px; }
.card-top { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.ftype { color: #E6EDF5; font-weight: 600; font-size: 15px; }
.sev { font-size: 11px; font-weight: 700; letter-spacing: .5px; }
.res { color: #8A97AB; font-size: 13px; font-family: ui-monospace, monospace; }
.card-meta { color: #6E7C92; font-size: 12px; margin-top: 4px; }
.timeline { display: flex; align-items: center; gap: 8px; color: #8A97AB; font-size: 12px; margin-top: 11px; }
.t-node { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.t-node.ok { background: #3DD68C; } .t-node.warn { background: #FFB454; }
.t-node.pending { background: transparent; border: 2px solid #FFB454; animation: ping 1.6s infinite; }
.t-line { flex: 0 0 26px; height: 1px; background: #2A3A52; }
.t-dur { color: #3DD68C; font-weight: 600; } .t-dur.warn { color: #FFB454; }
.pills { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 11px; }
.pill { background: #0E1626; border: 1px solid #243149; color: #A7B4C8; font-size: 11px; padding: 3px 8px; border-radius: 6px; }
.pill b { color: #00D4FF; font-weight: 600; }
.badge { align-self: center; font-size: 11px; font-weight: 700; letter-spacing: .6px; padding: 7px 13px; border-radius: 8px; white-space: nowrap; }
.badge.remediated { color: #3DD68C; background: rgba(61,214,140,.12); border: 1px solid rgba(61,214,140,.35); }
.badge.detected { color: #FFB454; background: rgba(255,180,84,.12); border: 1px solid rgba(255,180,84,.4); animation: glow 1.4s infinite; }
@keyframes glow { 0%, 100% { opacity: 1; } 50% { opacity: .5; } }
.empty { text-align: center; color: #6E7C92; padding: 64px 20px; border: 1px dashed #1E2A3F; border-radius: 14px; }
.aegis-footer { margin: 40px 0 10px; padding-top: 18px; border-top: 1px solid #1E2A3F;
  display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;
  color: #5A6B82; font-size: 12px; }
.aegis-footer a { color: #8A97AB; text-decoration: none; }
.aegis-footer a:hover { color: #00D4FF; }
.aegis-footer .links { display: flex; gap: 16px; }
</style>
"""


@st.cache_resource
def _table():
    return boto3.resource("dynamodb", region_name=REGION).Table(TABLE)


def load_findings():
    items, kwargs = [], {}
    while True:
        resp = _table().scan(**kwargs)
        items += resp.get("Items", [])
        key = resp.get("LastEvaluatedKey")
        if not key:
            break
        kwargs["ExclusiveStartKey"] = key
    # DynamoDB returns numbers as Decimal; normalise the epochs we render.
    for it in items:
        for k in ("detected_at", "remediated_at", "expires_at"):
            if it.get(k) is not None:
                it[k] = int(it[k])
    items.sort(key=lambda x: x.get("detected_at", 0), reverse=True)
    return items


def _hhmmss(ts):
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "—"


def _pills(controls):
    out = []
    for name, key in (("ENS", "ens"), ("NIS2", "nis2"), ("CIS", "cis_aws")):
        for cid in controls.get(key, []) or []:
            out.append(f'<span class="pill"><b>{name}</b> {cid}</span>')
    return "".join(out)


def _card(f):
    fid = f.get("finding_id", "UNKNOWN")
    label = FINDING_LABEL.get(fid, fid)
    sev = (f.get("severity") or "—").upper()
    color = SEVERITY_COLOR.get(sev, "#4DA3FF")
    resource = f.get("resource", "—")
    actor = (f.get("actor") or "—").split("/")[-1]
    action = f.get("action", "—")
    det, rem = f.get("detected_at"), f.get("remediated_at")

    if f.get("status") == "remediated" and rem and det:
        badge = '<span class="badge remediated">REMEDIATED</span>'
        timeline = (
            f'<span class="t-node ok"></span>Detected {_hhmmss(det)}'
            '<span class="t-line"></span>'
            f'<span class="t-dur">{rem - det}s</span>'
            '<span class="t-line"></span>'
            f'<span class="t-node ok"></span>Remediated {_hhmmss(rem)}'
        )
    else:
        badge = '<span class="badge detected">DETECTED</span>'
        timeline = (
            f'<span class="t-node warn"></span>Detected {_hhmmss(det)}'
            '<span class="t-line"></span>'
            '<span class="t-dur warn">remediating…</span>'
            '<span class="t-line"></span>'
            '<span class="t-node pending"></span>'
        )

    return (
        f'<div class="card" style="border-left-color:{color}">'
        '<div>'
        f'<div class="card-top"><span class="ftype">{label}</span>'
        f'<span class="sev" style="color:{color}">{sev}</span>'
        f'<span class="res">{resource}</span></div>'
        f'<div class="card-meta">by {actor} · {action}</div>'
        f'<div class="timeline">{timeline}</div>'
        f'<div class="pills">{_pills(f.get("controls", {}))}</div>'
        f'</div>{badge}</div>'
    )


@st.fragment(run_every=REFRESH_SECONDS)
def live_view():
    try:
        findings = load_findings()
    except Exception as e:  # noqa: BLE001
        st.error(
            f"Could not read the findings table ({TABLE} in {REGION}). "
            f"Check AWS credentials and that the core is deployed.\n\n{e}"
        )
        return

    total = len(findings)
    healed = [f for f in findings if f.get("status") == "remediated"]
    active = total - len(healed)
    ttrs = [f["remediated_at"] - f["detected_at"] for f in healed
            if f.get("remediated_at") and f.get("detected_at")]
    mttr = f"{sum(ttrs) / len(ttrs):.1f}s" if ttrs else "—"

    st.markdown(
        '<div class="live-bar"><span class="live-dot"></span>'
        f'Live · refreshing every {REFRESH_SECONDS}s · updated {datetime.now().strftime("%H:%M:%S")}'
        '</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="kpi-grid">'
        f'<div class="kpi"><div class="v">{total}</div><div class="l">Total findings</div></div>'
        f'<div class="kpi amber"><div class="v">{active}</div><div class="l">Active threats</div></div>'
        f'<div class="kpi green"><div class="v">{len(healed)}</div><div class="l">Auto-remediated</div></div>'
        f'<div class="kpi cyan"><div class="v">{mttr}</div><div class="l">Avg response</div></div>'
        '</div>',
        unsafe_allow_html=True,
    )

    if not findings:
        st.markdown(
            '<div class="empty">No findings yet. Deploy a scenario and run its attack '
            'to watch the pipeline detect and self-heal in real time.</div>',
            unsafe_allow_html=True,
        )
        return

    st.markdown('<div class="feed">' + "".join(_card(f) for f in findings) + "</div>",
                unsafe_allow_html=True)


st.markdown(CSS, unsafe_allow_html=True)
st.markdown(
    '<div class="brand">Aegis <span>Project</span></div>'
    '<div class="aegis-title">Live <span>Findings</span></div>'
    '<div class="aegis-sub">Self-healing pipeline — attack, detect and remediate, in real time</div>',
    unsafe_allow_html=True,
)
live_view()

st.markdown(
    '<div class="aegis-footer">'
    '<div>Built by Eloi Rey · Aegis Project</div>'
    '<div class="links">'
    '<a href="https://github.com/eloirey/aegis-project" target="_blank">GitHub</a>'
    '<a href="https://www.linkedin.com/in/eloi-rey-velardiez-93940338b" target="_blank">LinkedIn</a>'
    '<a href="https://eloirey.github.io" target="_blank">Portfolio</a>'
    '</div></div>',
    unsafe_allow_html=True,
)