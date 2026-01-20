import streamlit as st
import requests
import pandas as pd
import time
from typing import Dict, Any, Optional
import matplotlib.pyplot as plt

# Config
API_BASE = "http://127.0.0.1:8000"
st.set_page_config(page_title="Asset Risk Monitor", layout="wide")

def get_all_assets()->dict:
    """Get all assets at once """
    try:
        r = requests.get(f"{API_BASE}/assets", timeout=4)
        if r.status_code == 200:
            data: Optional[Dict[str, Any]] = r.json()
            # Ensure we return a dict (backend should return a dict)
            #print(data.get("assets").keys())
            return data.get("assets").keys() if isinstance(data, dict) else {}
        # Non-200 -> empty dict fallback (preserving your original behavior)
        return {}
    except Exception as e:
         return {}

#get all assets
ASSETS = get_all_assets()

def get_asset_risk(asset: str) -> dict:
    """Fetch per-asset risk from FastAPI backend."""
    try:
        r = requests.get(f"{API_BASE}/asset/{asset}", timeout=10)
        if r.status_code == 200:
            # print(r.json())
            return r.json()
        return {"risk_level": f"HTTP {r.status_code}", "confidence": 0.0, "reasons": [], "actions": []}
    except Exception as e:
        return {"risk_level": f"Error: {str(e)}", "confidence": 0.0, "reasons": [], "actions": []}

# ---- Read query param (stable API) to know which asset was clicked (e.g., ?asset=A1)
selected_asset = st.query_params.get("asset") # "A1" or None

# UI Header
st.markdown(
    """
    <style>
        /* Move title fully to the left */
        .block-container {
            padding-top: 1rem; /* reduces top padding */
        }
        h1 {
            text-align: left !important;
        }
    </style>
    """,
    unsafe_allow_html=True
)
st.title("Insight‑to‑Action (I2A) Defender")
st.markdown(
    """
    Evidence in, actions out.<br>
    <span style='font-size:14px; color:#555;'>
        Signals the pipeline transformation from insight to remediation.
    </span>
    """,
    unsafe_allow_html=True
)

# Controls
# col1, col2, col3 = st.columns([2, 1, 1])
# with col1:
#     auto_refresh = st.checkbox("Auto-refresh every 5 seconds", value=True)
# #with col2:
 # refresh_interval = st.slider("Refresh interval (seconds)", 5, 60, 10)
#with col2:
# if st.button("Force Refresh Now", type="primary"):
# st.cache_data.clear()
# st.rerun()

# Fetch data
with st.spinner("Fetching asset risks..."):
    asset_risks = {asset: get_asset_risk(asset) for asset in ASSETS}

# ---- Helpers ----
def get_risk_color(level: str) -> str:
    colors = {
        "SAFE": "🟢",
        "COMPROMISED": "🔴"
    }
    return colors.get(level, "⚪")
def risk_badge(level: str) -> str:
    badges = {
        "SAFE": "🟢 SAFE",
        "COMPROMISED": "🔴 COMPROMISED",
    }
    return badges.get(level, f"⚪ {level or 'Unknown'}")
def make_asset_link(asset: str) -> str:
    """Return a real HTML hyperlink for the Asset cell."""
    return f"<a href='?asset={asset}' style='text-decoration:none; font-weight:bold'>{asset}</a>"
# -------------------------------
st.subheader("Asset Details")
# Build table rows
rows = []
for asset in ASSETS:
    d = asset_risks.get(asset, {})
    level = d.get("risk_level", "Unknown")
    conf = float(d.get("confidence", 0.0))
    rows.append({
        "Asset": make_asset_link(asset.upper()), # clickable link
        "Risk": risk_badge(level),
        "prediction": level, # raw for filtering
        #"Confidence": conf,
        "Confidence %": f"{conf*100:.1f}%"
    })
df = pd.DataFrame(rows)

# Handle empty DataFrame
if df.empty:
    st.warning("No assets found. Make sure the API server is running: `python api.py`")
    st.stop()

# --- Filters ---
with st.container():
    c1, c2, c3 = st.columns([2, 2, 1])
    with c1:
        asset_filter = st.text_input("Filter by asset name", "")
    with c2:
        risk_filter = st.multiselect(
            "Filter by risk level",
            options=sorted(df["prediction"].dropna().unique().tolist()),
            default=[],
        )
    # with c3:
    # min_conf = st.slider("Min confidence", 0.0, 1.0, 0.0, 0.05)
# Apply filters (search within the anchor text; do not .upper() here)
filtered_df = df.copy()
if asset_filter:
    filtered_df = filtered_df[
        filtered_df["Asset"].str.contains(asset_filter.strip(), case=False, na=False)
    ]
if risk_filter:
    filtered_df = filtered_df[filtered_df["prediction"].isin(risk_filter)]
#filtered_df = filtered_df[filtered_df["Confidence"] >= min_conf]
# -------------------------------
# Render table and pie chart side by side
col_table, col_chart = st.columns([3, 2])
with col_table:
    # Render table as HTML so <a> links are clickable
    # Center "Risk" heading only
    st.markdown("""
    <style>
    table th:nth-child(2) {
        text-align: center !important;
    }
    </style>
    """, unsafe_allow_html=True)
    display_df = filtered_df[["Asset", "Risk", "Confidence %"]]
    st.write(display_df.to_html(escape=False, index=False), unsafe_allow_html=True)
    # CSV Download (drop emoji-only Risk column)
    download_df = filtered_df.drop(columns=["Risk"])
    csv = download_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="Download Table as CSV",
        data=csv,
        file_name=f"asset_risks_{time.strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv"
    )
with col_chart:
    st.subheader("Risk Distribution")
    risk_counts = filtered_df['prediction'].value_counts()
    if not risk_counts.empty:
        fig1, ax1 = plt.subplots(figsize=(6, 4))
        colors_dict = {
            "SAFE": "#70C247",

            "COMPROMISED": "#CC183C",

        }
        colors = [colors_dict.get(label, "#808080") for label in risk_counts.index]
        wedges, texts, autotexts = ax1.pie(risk_counts.values, labels=risk_counts.index, autopct='%1.1f%%', colors=colors, startangle=90)
        ax1.set_title('Distribution of Risk Levels')
        # Improve text visibility
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
        st.pyplot(fig1)
        plt.close(fig1)  # Prevent duplicate display
    else:
        st.info("No data to display.")
st.divider()
# -------------------------------
# 🔍 INDIVIDUAL ASSET DETAILS
# -------------------------------
if selected_asset:
    api_key = selected_asset.lower()
    data = asset_risks.get(api_key, {}) or {}
    risk_level = data.get("risk_level", "Unknown")
    confidence = float(data.get("confidence", 0.0) or 0.0)
    suspicious_activity = data.get("suspicious_activity", []) or []
    reasons = data.get("reasons", []) or []
    actions = data.get("actions", []) or []
    st.markdown(f"## Asset: {selected_asset}")
    st.markdown(f"{get_risk_color(risk_level)} **{risk_level}**")
    st.progress(confidence)
    st.caption(f"Confidence: {confidence:.2%}")
    st.subheader("Suspicious Data Fields")
    if suspicious_activity:
        for sa in suspicious_activity:
            st.write(f"• {sa}")
    else:
        st.caption("No suspicious activity found.")
    st.subheader("Reasons")
    if reasons:
        for r in reasons:
            st.write(f"• {r}")
    else:
        st.caption("No reasons available.")
    st.subheader("Remediation")
    if actions:
        for a in actions:
            st.write(f"• {a}")
    else:
        st.caption("No actions available.")
    # Optional: clear selection button (removes ?asset= param)
    if st.button("Clear selection"):
        st.query_params.pop("asset", None)
        st.rerun()
else:
    st.caption("Click an asset name (e.g., **A1**) in the table above to view details.")
# Footer
st.markdown("---")
st.caption(f"Last updated: {time.strftime('%H:%M:%S')} • Monitoring {len(ASSETS)} assets")
# Auto-refresh
# if auto_refresh:
#    time.sleep(30)
#    st.rerun()