import streamlit as st
import pandas as pd
import time
import os
import json
import io
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

# --- CONFIGURATION ---
st.set_page_config(
    page_title="OmniSecure Defense Center", 
    page_icon="🛡️", 
    layout="wide"
)

st.markdown("""
    <style>
    .stApp {background-color: #0e1117;}
    .metric-card {background-color: #1f2937; padding: 15px; border-radius: 10px;}
    </style>
    """, unsafe_allow_html=True)

# --- SIDEBAR ---
with st.sidebar:
    st.title("🛡️ OmniSecure")
    st.caption("Intelligent Email Defense & Payload Forensics")
    st.markdown("---")
    page = st.radio("Navigation", ["🔴 Live Monitoring", "🔒 Quarantine Vault", "⚙️ Configuration"])
    auto_refresh = st.checkbox("Enable Auto-Refresh", value=True)
    st.markdown("---")
    st.markdown("### 👨‍💻 Developed By")
    st.markdown("**M.Younus**")
    st.markdown("**Hifazat Ali**")
    st.markdown("**Mohsin Ali**")
    st.markdown("---")
    st.caption("🎓 Batch: **Cyb-22S**")
    st.caption("📍 Sindh Madressatul Islam University")

# --- ON-DEMAND PDF GENERATOR ---
def generate_pdf_bytes(data):
    """Generates PDF file in memory (RAM) and returns bytes."""
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    
    # 1. Header
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, 750, "🛡️ OmniSecure Forensic Report")
    c.setFont("Helvetica", 12)
    c.drawString(400, 750, f"Date: {data.get('timestamp', 'Unknown')[:10]}")
    c.line(50, 730, 550, 730)

    # 2. Banner
    score = data.get('score', 0)
    color = (1, 0, 0) if score > 75 else (1, 0.5, 0)
    c.setFillColorRGB(*color)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, 700, f"THREAT LEVEL: {data.get('severity', 'UNKNOWN')} (Score: {score}/100)")
    c.setFillColorRGB(0, 0, 0)

    # 3. Metadata
    y = 660
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "1. Email Metadata")
    c.setFont("Helvetica", 10)
    c.drawString(70, y-20, f"Subject: {data.get('subject', 'N/A')[:60]}")
    c.drawString(70, y-35, f"Sender: {data.get('sender', 'N/A')[:60]}")

    # 4. Analysis
    y = 600
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "2. Analysis Breakdown")
    c.setFont("Helvetica", 10)
    
    items = [
        f"• AI Verdict: {data.get('ai_verdict', 'Pass')}",
        f"• VT Verdict: {data.get('vt_verdict', 'Pass')}",
        f"• Attachment Status: {data.get('att_verdict', 'None')}",
        f"• QR Code Status: {data.get('qr_verdict', 'None')}"
    ]
    
    for i, item in enumerate(items):
        c.drawString(70, y - 20 - (i*15), item)

    # 5. Artifacts
    y = y - 20 - (len(items)*15) - 20
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "3. Detected Artifacts")
    c.setFont("Courier", 9)
    y -= 20
    
    artifacts = data.get('bad_artifacts', [])
    if artifacts:
        for artifact in artifacts[:6]: # Show top 6
            c.drawString(70, y, f"- {str(artifact)[:80]}")
            y -= 15
    else:
        c.drawString(70, y, "- No specific artifacts isolated.")
        y -= 15

    # 6. Raw Evidence (Cleaned)
    y -= 20
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "4. Text Content Preview")
    c.setFont("Courier", 9)
    y -= 20
    
    raw_body = data.get('body_snippet', '')
    clean_words = [w for w in raw_body.split() if len(w) < 40 and "<" not in w]
    clean_text = " ".join(clean_words)[:600]
    
    text_object = c.beginText(50, y)
    text_object.setFont("Courier", 9)
    wrapper = [clean_text[i:i+90] for i in range(0, len(clean_text), 90)]
    for line in wrapper:
        text_object.textLine(line)
    c.drawText(text_object)

    c.save()
    buffer.seek(0)
    return buffer

# --- LOAD DATA ---
def load_threat_reports():
    reports = []
    if not os.path.exists("reports"): return pd.DataFrame()
    files = sorted(os.listdir("reports"), reverse=True)
    for f in files:
        if f.endswith(".json"):
            filepath = os.path.join("reports", f)
            with open(filepath, 'r') as file:
                try:
                    data = json.load(file)
                    reports.append(data)
                except: pass
    return pd.DataFrame(reports)

# --- PAGE 1: LIVE MONITORING ---
if page == "🔴 Live Monitoring":
    st.title("📡 Live Threat Intelligence")
    st.markdown(f"**System:** OmniSecure: Intelligent Email Defense & Payload Forensics")
    
    log_data = []
    if os.path.exists("detector_log.txt"):
        with open("detector_log.txt", "r", encoding="utf-8") as f: log_data = f.readlines()
    
    threat_df = load_threat_reports()
    real_scan_count = sum(1 for line in log_data if "Scanning:" in line)
    
    kpi1, kpi2, kpi3 = st.columns(3)
    kpi1.metric("Emails Scanned", real_scan_count)
    kpi2.metric("Threats Detected", len(threat_df))
    kpi3.metric("System Status", "ACTIVE", delta_color="normal")
    st.markdown("---")
    
    c1, c2 = st.columns([2, 1])
    with c1:
        st.subheader("🚨 Recent Alerts")
        if not threat_df.empty:
            st.dataframe(
                threat_df[['timestamp', 'subject', 'severity', 'score']], 
                use_container_width=True, hide_index=True
            )
            
            st.subheader("📄 Forensic Reporting")
            unique_subjects = threat_df['subject'].unique()
            selected_subject = st.selectbox("Select Threat for Report:", unique_subjects)
            
            if selected_subject:
                # Get the full JSON data for this subject
                row_data = threat_df[threat_df['subject'] == selected_subject].iloc[0].to_dict()
                
                st.info(f"Selected: **{row_data['subject']}**")
                
                # GENERATE PDF ON THE FLY
                pdf_bytes = generate_pdf_bytes(row_data)
                
                # Clean filename for download
                safe_name = "".join([c for c in row_data['subject'] if c.isalnum()]).strip()[:20]
                
                st.download_button(
                    label="⬇️ Download Forensic PDF Report",
                    data=pdf_bytes,
                    file_name=f"Report_{safe_name}.pdf",
                    mime="application/pdf"
                )
        else:
            st.success("✅ No Active Threats. System Clean.")
    
    with c2:
        st.subheader("📜 Live Engine Logs")
        if log_data: st.code("".join(log_data[-15:]), language="bash")
        else: st.info("Waiting for logs...")

    if auto_refresh:
        time.sleep(2)
        st.rerun()

# --- PAGE 2: QUARANTINE VAULT ---
elif page == "🔒 Quarantine Vault":
    st.title("🔒 Quarantine Vault")
    threat_df = load_threat_reports()
    
    if not threat_df.empty:
        try:
            high_risk = threat_df[pd.to_numeric(threat_df['score'], errors='coerce') >= 70]
        except: high_risk = threat_df
            
        if not high_risk.empty:
            unique_high_risk = high_risk.drop_duplicates(subset=['subject'], keep='first')
            for index, row in unique_high_risk.iterrows():
                with st.expander(f"🔴 {row['subject']} (Score: {row['score']})"):
                    c1, c2 = st.columns(2)
                    c1.write(f"**Sender:** {row['sender']}")
                    c1.write(f"**Timestamp:** {row['timestamp']}")
                    c2.error(f"**Verdict:** {row['severity']}")
                    st.write(f"**Details:** {row.get('details', 'N/A')}")
        else:
            st.success("No Critical Threats in Vault.")
    else:
        st.success("Vault Empty.")

elif page == "⚙️ Configuration":
    st.title("⚙️ System Configuration")
    if os.path.exists("config.json"):
        with open("config.json") as f: st.json(json.load(f))
    else: st.warning("Configuration file not found.")