# dashboard/app.py
import streamlit as st

st.set_page_config(
    page_title="Aegis Project",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Shared canvas so both pages sit on the same Aegis navy.
st.markdown("<style>.stApp{background:#0B0F1A;}</style>", unsafe_allow_html=True)

pages = [
    st.Page("views/live_findings.py", title="Live Findings", default=True),
    st.Page("views/coverage.py", title="Compliance Coverage"),
]
st.navigation(pages).run()