from src import (
    detect_sensitive_data,
    apply_protection,
    calculate_risk_assessment,
    evaluate_utility,
    generate_markdown_report,
    scan_document,
    add_laplace_noise,
    generate_synthetic_dataset,
)
from src.connectors.sqlite_connector import inspect_sqlite_database

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from io import BytesIO
import os
import json

st.set_page_config(
    page_title="Data Privacy Guardian",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# UI Layer Enhancement Modules
try:
    from ui import inject_theme, render_background, render_soc_header, render_terminal_feed, render_sidebar_footer, create_cyber_gauge, create_category_donut
    UI_AVAILABLE = True
except Exception:
    UI_AVAILABLE = False

# Fallback switch: default ON, can be toggled OFF to restore original UI completely
use_new_ui = st.sidebar.toggle("⚡ Use Cyber SOC UI v2", value=True, key="USE_NEW_UI")

if use_new_ui and UI_AVAILABLE:
    # 1. Inject Glassmorphism Design System
    inject_theme()
    
    # 2. Interactive Background Canvas with user toggle
    bg_fx_enabled = st.sidebar.toggle("🌐 Background FX", value=True, key="ui2_bg_fx")
    render_background(enabled=bg_fx_enabled)
else:
    # Original UI Fallback Styling
    st.markdown("""
    <div style="background:#091222; border:1px solid #1e3a5f; border-radius:10px; padding:18px; margin-bottom:20px;">
        <h2 style="color:#ffffff; margin:0;">🛡️ DATA PRIVACY GUARDIAN [CLASSIC]</h2>
        <div style="color:#00f2fe; font-size:12px; margin-top:5px;">● LOCAL PRIVACY ENGINE</div>
    </div>
    """, unsafe_allow_html=True)

@st.cache_data(show_spinner=False)
def load_dataset(file_bytes, filename):
    if filename.lower().endswith(".csv"):
        try:
            return pd.read_csv(BytesIO(file_bytes))
        except UnicodeDecodeError:
            return pd.read_csv(BytesIO(file_bytes), encoding="latin-1")
    return pd.read_excel(BytesIO(file_bytes), engine="openpyxl")


def format_bytes(size):
    if size < 1024:
        return f"{size} B"
    if size < 1024**2:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024**2):.2f} MB"


# Sidebar Navigation
st.sidebar.markdown("### 🎛️ NAVIGATION")

# Master list of all supported modules
ALL_MODULES = [
    "🛡️ Command Center Dashboard",
    "📊 Tabular Datasets (CSV/Excel)",
    "📄 Documents & Code (PDF/DOCX/TXT/Code)",
    "🖼️ Photos & Screenshots (EXIF / OCR / Redaction)",
    "🎙️ Audio/Video Transcripts & Subtitles (.srt/.vtt)",
    "🗄️ Relational Databases (SQLite / SQL)",
    "🌐 Web Links, Trackers & Attack Script Inspector",
    "💻 Git Repositories & Project Folders",
    "🧬 Synthetic Data Generator",
    "📜 Scan Audit History & Logs"
]

# Hidden modules for clean streamlined view (backend code remains intact)
HIDDEN_MODULES = {
    "🧬 Synthetic Data Generator",
    "📜 Scan Audit History & Logs",
    "🎙️ Audio/Video Transcripts & Subtitles (.srt/.vtt)",
    "🗄️ Relational Databases (SQLite / SQL)",
}

MODULE_LIST = [m for m in ALL_MODULES if m not in HIDDEN_MODULES]

# Initialize navigation state
if "nav_mode_radio" not in st.session_state:
    st.session_state["nav_mode_radio"] = MODULE_LIST[0]
elif st.session_state["nav_mode_radio"] not in MODULE_LIST:
    st.session_state["nav_mode_radio"] = MODULE_LIST[0]

def set_mode(new_mode):
    st.session_state["nav_mode_radio"] = new_mode

mode = st.sidebar.radio(
    "Choose a Privacy Tool:",
    MODULE_LIST,
    key="nav_mode_radio"
)

# Render Sidebar Footer
if use_new_ui and UI_AVAILABLE:
    render_sidebar_footer()

# Top Friendly Header
if use_new_ui and UI_AVAILABLE:
    clean_name = mode.split(" ", 1)[-1] if " " in mode else mode
    render_soc_header(clean_name)

# ----------------------------------------------------
# MODE 0: HOMEPAGE / SERVICES OVERVIEW (Simple & Friendly)
# ----------------------------------------------------
if mode == "🛡️ Command Center Dashboard":
    from src.audit_history import get_scan_history
    history = get_scan_history()
    
    total_scans = len(history)
    total_findings = sum(item.get("total_findings", 0) for item in history) if total_scans > 0 else 0

    # 1. Warm Welcome & Project Overview
    st.markdown("""
    <div style="background: linear-gradient(135deg, rgba(13, 27, 42, 0.9) 0%, rgba(20, 42, 69, 0.75) 100%); 
                border: 1px solid #1e3a5f; border-radius: 12px; padding: 22px 24px; margin-bottom: 25px;">
        <h2 style="color: #ffffff; margin: 0 0 8px 0; font-size: 24px;">Welcome to Data Privacy Guardian</h2>
        <p style="color: #94a3b8; font-size: 15px; margin: 0 0 14px 0; line-height: 1.6;">
            Your personal, <b>100% offline & air-gapped data sanitization suite</b>. 
            Safely detect sensitive info (names, phone numbers, passwords, API keys, medical data) 
            and automatically clean or mask them before you share files with AI models or teammates. 
            <b>Nothing you upload ever leaves your computer.</b>
        </p>
        <div style="display: flex; gap: 10px; flex-wrap: wrap;">
            <span style="background: rgba(0, 242, 254, 0.12); color: #00f2fe; border: 1px solid rgba(0, 242, 254, 0.3); padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600;">🔒 Completely Air-Gapped</span>
            <span style="background: rgba(16, 185, 129, 0.12); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600;">⚡ Instant Local Scans</span>
            <span style="background: rgba(56, 189, 248, 0.12); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600;">🛡️ Zero Cloud Egress</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # 2. Service Options & "What is this for?" Cards
    st.subheader("🚀 Choose What You Want to Protect")
    st.write("Click on any tool below or select it from the left menu to start:")

    sc1, sc2 = st.columns(2)

    with sc1:
        # Service 1: Tabular Datasets
        st.markdown("""
        <div style="background: rgba(13, 27, 42, 0.65); border: 1px solid #1e3a5f; border-radius: 10px; padding: 18px; margin-bottom: 16px;">
            <h4 style="color: #00f2fe; margin: 0 0 6px 0;">📊 1. Tabular Datasets (CSV & Excel)</h4>
            <p style="color: #cbd5e1; font-size: 13.5px; margin-bottom: 8px;">
                <b>What it does:</b> Finds customer names, emails, phone numbers, and salaries in spreadsheet files.
            </p>
            <p style="color: #94a3b8; font-size: 13px; margin-bottom: 12px;">
                <b>Best for:</b> Cleaning customer or patient spreadsheets with Differential Privacy or Masking before analysis.
            </p>
        </div>
        """, unsafe_allow_html=True)
        st.button("Open Tabular Data Cleaner →", use_container_width=True, key="btn_open_tabular", on_click=set_mode, args=("📊 Tabular Datasets (CSV/Excel)",))

        st.write("")

        # Service 3: Photos & Screenshots
        st.markdown("""
        <div style="background: rgba(13, 27, 42, 0.65); border: 1px solid #1e3a5f; border-radius: 10px; padding: 18px; margin-bottom: 16px;">
            <h4 style="color: #38bdf8; margin: 0 0 6px 0;">🖼️ 3. Photos & Screenshots</h4>
            <p style="color: #cbd5e1; font-size: 13.5px; margin-bottom: 8px;">
                <b>What it does:</b> Reads text inside pictures (OCR), blacks out sensitive words, and strips hidden GPS camera data (EXIF).
            </p>
            <p style="color: #94a3b8; font-size: 13px; margin-bottom: 12px;">
                <b>Best for:</b> Redacting ID cards, receipts, or bug screenshots before uploading them anywhere.
            </p>
        </div>
        """, unsafe_allow_html=True)
        st.button("Open Photo & Screenshot Redactor →", use_container_width=True, key="btn_open_photos", on_click=set_mode, args=("🖼️ Photos & Screenshots (EXIF / OCR / Redaction)",))

        st.write("")

        # Service 5: Git Repositories
        st.markdown("""
        <div style="background: rgba(13, 27, 42, 0.65); border: 1px solid #1e3a5f; border-radius: 10px; padding: 18px; margin-bottom: 16px;">
            <h4 style="color: #818cf8; margin: 0 0 6px 0;">💻 5. Project Folders & Codebases</h4>
            <p style="color: #cbd5e1; font-size: 13.5px; margin-bottom: 8px;">
                <b>What it does:</b> Scans an entire software folder or Git repo for accidentally hardcoded secrets.
            </p>
            <p style="color: #94a3b8; font-size: 13px; margin-bottom: 12px;">
                <b>Best for:</b> Making sure you don't commit secret credentials to GitHub.
            </p>
        </div>
        """, unsafe_allow_html=True)
        st.button("Open Codebase & Project Scanner →", use_container_width=True, key="btn_open_repo", on_click=set_mode, args=("💻 Git Repositories & Project Folders",))

    with sc2:
        # Service 2: Documents & Code Files
        st.markdown("""
        <div style="background: rgba(13, 27, 42, 0.65); border: 1px solid #1e3a5f; border-radius: 10px; padding: 18px; margin-bottom: 16px;">
            <h4 style="color: #10b981; margin: 0 0 6px 0;">📄 2. Documents & Text Files (PDF / Word / TXT)</h4>
            <p style="color: #cbd5e1; font-size: 13.5px; margin-bottom: 8px;">
                <b>What it does:</b> Scans PDFs, Word documents, text files, and scripts for passwords and private records.
            </p>
            <p style="color: #94a3b8; font-size: 13px; margin-bottom: 12px;">
                <b>Best for:</b> Redacting confidential contracts or removing secrets from code files before sharing.
            </p>
        </div>
        """, unsafe_allow_html=True)
        st.button("Open Document & Secret Scanner →", use_container_width=True, key="btn_open_docs", on_click=set_mode, args=("📄 Documents & Code (PDF/DOCX/TXT/Code)",))

        st.write("")

        # Service 4: Web Links Inspector
        st.markdown("""
        <div style="background: rgba(13, 27, 42, 0.65); border: 1px solid #1e3a5f; border-radius: 10px; padding: 18px; margin-bottom: 16px;">
            <h4 style="color: #f59e0b; margin: 0 0 6px 0;">🌐 4. Web Links & Trackers Inspector</h4>
            <p style="color: #cbd5e1; font-size: 13.5px; margin-bottom: 8px;">
                <b>What it does:</b> Inspects web links for tracking IDs (UTM, Facebook/Google click tags) and attack scripts.
            </p>
            <p style="color: #94a3b8; font-size: 13px; margin-bottom: 12px;">
                <b>Best for:</b> Cleaning ugly tracking URLs into safe, private links before clicking or sending.
            </p>
        </div>
        """, unsafe_allow_html=True)
        st.button("Open Link & Tracker Inspector →", use_container_width=True, key="btn_open_links", on_click=set_mode, args=("🌐 Web Links, Trackers & Attack Script Inspector",))

        st.write("")

        # Quick Summary Stats Box
        st.markdown(f"""
        <div style="background: rgba(13, 27, 42, 0.45); border: 1px dashed #1e3a5f; border-radius: 10px; padding: 16px; text-align: center;">
            <div style="color: #94a3b8; font-size: 13px; margin-bottom: 4px;">Session Activity</div>
            <div style="font-size: 20px; font-weight: 700; color: #ffffff;">{total_scans} Scans Completed &bull; {total_findings} Sensitive Items Found</div>
            <div style="color: #10b981; font-size: 12px; margin-top: 4px;">● System Ready for next task</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.caption("Need help? Choose any service card above or click on the left sidebar to begin.")

# ----------------------------------------------------
# MODE 1: TABULAR DATASETS (With PETs & Differential Privacy)
# ----------------------------------------------------
elif mode == "📊 Tabular Datasets (CSV/Excel)":
    st.subheader("📊 Tabular Datasets Cleaner")
    st.write("Scan spreadsheet files (**CSV**, **Excel**) for customer names, emails, phone numbers, and salaries. Automatically mask or redact them before sharing.")

    # Easy In-Page File Ingestion
    up_card1, up_card2 = st.columns([3, 2])
    with up_card1:
        uploaded_file = st.file_uploader(
            "📁 Select or Drop a CSV or Excel file:",
            type=["csv", "xlsx"],
            help="Your file is processed locally on your device."
        )
    with up_card2:
        st.write("**Or try with test data:**")
        load_sample = st.button("⚡ Load Demo Medical/Customer Dataset", use_container_width=True)

    active_df = None
    file_name = ""
    file_size_str = ""

    if load_sample:
        sample_path = os.path.join(os.path.dirname(__file__), "sample_data", "sample_dataset.csv")
        if os.path.exists(sample_path):
            active_df = pd.read_csv(sample_path)
            file_name = "sample_dataset.csv"
            file_size_str = format_bytes(os.path.getsize(sample_path))
            st.session_state["tab_df"] = active_df
            st.session_state["tab_name"] = file_name
            st.session_state["tab_size"] = file_size_str

    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()
        active_df = load_dataset(file_bytes, uploaded_file.name)
        file_name = uploaded_file.name
        file_size_str = format_bytes(len(file_bytes))
        st.session_state["tab_df"] = active_df
        st.session_state["tab_name"] = file_name
        st.session_state["tab_size"] = file_size_str
    elif "tab_df" in st.session_state:
        active_df = st.session_state["tab_df"]
        file_name = st.session_state["tab_name"]
        file_size_str = st.session_state["tab_size"]

    if active_df is not None:
        df = active_df.copy()

        if df.empty:
            st.warning("The selected dataset contains no data rows or columns.")
        else:
            # 1. Overview
            with st.expander("📊 1. Dataset Overview & Preview", expanded=True):
                col1, col2, col3, col4, col5 = st.columns(5)
                col1.metric("Total Rows", f"{df.shape[0]:,}")
                col2.metric("Total Columns", f"{df.shape[1]:,}")
                col3.metric("Missing Cells", f"{int(df.isna().sum().sum()):,}")
                col4.metric("Duplicate Rows", f"{int(df.duplicated().sum()):,}")
                col5.metric("File Size", file_size_str)

                st.caption(f"File: `{file_name}`")
                st.dataframe(df.head(10), use_container_width=True)

            # 2. Sensitive Information Discovery
            st.subheader("🔍 2. Sensitive Information Discovery")
            findings = detect_sensitive_data(df)

            if findings.empty:
                st.success("No supported sensitive-data indicators were detected by the rule patterns.")
            else:
                direct_count = len(findings[findings["Role"] == "Direct Identifier"])
                quasi_count = len(findings[findings["Role"] == "Quasi-Identifier"])
                sens_count = len(findings[findings["Role"] == "Sensitive Attribute"])

                fcol1, fcol2, fcol3 = st.columns(3)
                fcol1.metric("Direct Identifiers (PII)", direct_count, help="Names, Emails, Phones, IDs")
                fcol2.metric("Quasi-Identifiers", quasi_count, help="Age, ZIP, Gender (Can identify when linked)")
                fcol3.metric("Sensitive Attributes", sens_count, help="Salaries, Diagnoses, Financials")

                st.dataframe(findings, use_container_width=True)

            # 3. Protection Configuration
            st.subheader("🛡️ 3. Privacy Protection & PETs Configuration")
            detected_cols = findings["Column"].unique().tolist() if not findings.empty else []
            all_cols = list(df.columns)

            col_selection = st.multiselect(
                "Select columns to protect:",
                options=all_cols,
                default=[c for c in detected_cols if c in all_cols],
                help="Select columns to apply redaction, masking, generalization, pseudonymization, differential privacy, or removal."
            )

            column_actions = {}
            if col_selection:
                st.write("#### Configure Methods for Selected Columns:")
                grid_cols = st.columns(min(len(col_selection), 3))
                
                for i, c in enumerate(col_selection):
                    with grid_cols[i % len(grid_cols)]:
                        st.markdown(f"**Column: `{c}`**")
                        role_guess = "Direct Identifier"
                        if not findings.empty:
                            matched = findings[findings["Column"] == c]
                            if not matched.empty:
                                role_guess = matched.iloc[0]["Role"]
                        
                        default_idx = 0
                        if role_guess == "Direct Identifier":
                            default_idx = 1 # Mask or Redact
                        elif role_guess == "Quasi-Identifier":
                            default_idx = 3 # Generalize
                        elif role_guess == "Sensitive Attribute":
                            default_idx = 3 # Generalize or Redact

                        method = st.selectbox(
                            f"Action for {c}",
                            options=["Redact", "Mask", "Pseudonymize", "Generalize", "Differential Privacy", "Remove"],
                            index=default_idx,
                            key=f"method_{c}"
                        )

                        params = {}
                        if method == "Generalize":
                            step = st.number_input(f"Bin interval for {c}", min_value=1, max_value=100000, value=10, key=f"step_{c}")
                            params["step"] = float(step)
                        elif method == "Mask":
                            keep = st.slider(f"Unmasked edge chars for {c}", 0, 4, 1, key=f"mask_{c}")
                            params["keep_first"] = keep
                            params["keep_last"] = keep
                        elif method == "Pseudonymize":
                            params["salt"] = "guardian_secret_salt"
                        elif method == "Differential Privacy":
                            eps = st.slider(f"Epsilon (ε) budget for {c}", min_value=0.1, max_value=5.0, value=1.0, step=0.1, key=f"eps_{c}", help="Lower ε = more noise & stronger privacy.")
                            params["epsilon"] = float(eps)

                        column_actions[c] = {"method": method, "params": params}

            protected_df = apply_protection(df, column_actions)

            # 4. Preview
            with st.expander("👁️ 4. Protected Dataset Preview", expanded=True):
                st.dataframe(protected_df.head(10), use_container_width=True)

            # 5. Risk Assessment (k-anonymity & l-diversity)
            st.subheader("⚖️ 5. Advanced Privacy Risk, k-Anonymity & l-Diversity")
            risk_data = calculate_risk_assessment(df, protected_df, findings, column_actions)

            r_col1, r_col2, r_col3, r_col4, r_col5 = st.columns(5)
            r_col1.metric("Overall Risk Score", f"{risk_data['overall_risk_score']}/100", delta=risk_data["risk_level"], delta_color="inverse")
            r_col2.metric("Singling-Out Risk", f"{risk_data['reidentification_risk']}%")
            r_col3.metric("Min k-Anonymity", f"k = {risk_data['k_anonymity_estimate']}")
            r_col4.metric("Min l-Diversity", f"l = {risk_data.get('l_diversity_estimate', 1)}")
            r_col5.metric("Detection Coverage", f"{risk_data['coverage_percentage']}%")

            # Tactical Cybersecurity Threat Gauge
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=risk_data['overall_risk_score'],
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "TACTICAL RE-IDENTIFICATION & EXPOSURE INDEX", 'font': {'color': '#94a3b8', 'size': 14}},
                number={'font': {'color': '#38bdf8', 'size': 38, 'family': 'JetBrains Mono'}},
                gauge={
                    'axis': {'range': [0, 100], 'tickcolor': '#475569'},
                    'bar': {'color': "#00f2fe"},
                    'bgcolor': "#0b132b",
                    'borderwidth': 1,
                    'bordercolor': "#1e293b",
                    'steps': [
                        {'range': [0, 35], 'color': "rgba(16, 185, 129, 0.25)"},
                        {'range': [35, 70], 'color': "rgba(245, 158, 11, 0.25)"},
                        {'range': [70, 100], 'color': "rgba(239, 68, 68, 0.35)"},
                    ],
                    'threshold': {
                        'line': {'color': "#ef4444", 'width': 3},
                        'thickness': 0.8,
                        'value': 70
                    }
                }
            ))
            fig_gauge.update_layout(
                paper_bgcolor="#091222",
                plot_bgcolor="#091222",
                height=250,
                margin=dict(l=20, r=20, t=35, b=15)
            )
            st.plotly_chart(fig_gauge, use_container_width=True)

            st.markdown("**🛡️ Risk Mitigation Recommendations:**")
            for rec in risk_data["recommendations"]:
                st.info(f"👉 {rec}")

            # 6. Utility
            st.subheader("📈 6. Analytical Utility & Trade-Off Assessment")
            utility_data = evaluate_utility(df, protected_df)

            u_col1, u_col2, u_col3 = st.columns(3)
            u_col1.metric("Overall Utility Score", f"{utility_data['overall_utility_score']}%")
            u_col2.metric("Row Retention", f"{utility_data['rows_retained_pct']}%")
            u_col3.metric("Column Retention", f"{utility_data['columns_retained_pct']}%")

            if not utility_data["numeric_metrics"].empty:
                st.write("##### Numerical Distribution Preservation:")
                st.dataframe(utility_data["numeric_metrics"], use_container_width=True)

            if not utility_data["categorical_metrics"].empty:
                st.write("##### Categorical Diversity Preservation:")
                st.dataframe(utility_data["categorical_metrics"], use_container_width=True)

            # 7. Export
            st.subheader("📥 7. Export Protected Dataset & Audit Report")
            report_md = generate_markdown_report(
                file_name,
                df.shape,
                protected_df.shape,
                findings,
                risk_data,
                utility_data,
                column_actions
            )

            d_col1, d_col2 = st.columns(2)
            with d_col1:
                csv_data = protected_df.to_csv(index=False).encode("utf-8")
                st.download_button(
                    "⬇️ Download Protected Dataset (CSV)",
                    data=csv_data,
                    file_name=f"protected_{file_name if file_name.endswith('.csv') else file_name + '.csv'}",
                    mime="text/csv",
                    use_container_width=True
                )

            with d_col2:
                st.download_button(
                    "📄 Download Privacy Audit Report (Markdown)",
                    data=report_md.encode("utf-8"),
                    file_name=f"privacy_audit_report_{file_name}.md",
                    mime="text/markdown",
                    use_container_width=True
                )
    else:
        st.info("👈 Upload a dataset via the sidebar or click **'Load Sample Medical/Customer Dataset'** to begin.")

# ----------------------------------------------------
# MODE 2: DOCUMENTS, CODE & SECRETS
# ----------------------------------------------------
elif mode == "📄 Documents & Code (PDF/DOCX/TXT/Code)":
    st.subheader("📄 Multi-Format Document, Code & Secret Scanner")
    st.write(
        "Scan unstructured text documents (**PDF**, **DOCX**, **TXT**, **Markdown**) or "
        "configuration/code files (**JSON**, **YAML**, **Python**, **.env**, **logs**) for PII, "
        "passwords, database connection strings, and exposed API tokens."
    )

    doc_upload = st.file_uploader(
        "Upload a Document, Code, or Log File",
        type=["pdf", "docx", "txt", "md", "json", "py", "env", "log", "yaml", "yml"],
        help="Supports PDF, Word Documents, Plain Text, Code, and Log files."
    )

    demo_choice = st.selectbox(
        "Or test with a pre-configured scenario:",
        ["None (Upload your own)", "Sample Confidential Agreement (DOCX/TXT)", "Exposed Secrets & API Keys (.env / Code)"]
    )

    raw_bytes = None
    doc_name = ""

    if demo_choice == "Sample Confidential Agreement (DOCX/TXT)":
        sample_text = """
CONFIDENTIAL SERVICE AGREEMENT
Customer Name: Johnathan Doe
Contact Email: j.doe@megacorp.internal
Direct Phone: +1-555-891-2345
Billing SSN: 123-45-6789
Home Address: 742 Evergreen Terrace, San Francisco, CA
Credit Card: 4111111111111111
Diagnosis Note: Patient reported severe chronic migraine symptoms.
        """.strip()
        raw_bytes = sample_text.encode("utf-8")
        doc_name = "sample_agreement.txt"
    elif demo_choice == "Exposed Secrets & API Keys (.env / Code)":
        sample_code = """
# Production Configuration File
ENVIRONMENT=production
DB_URI="postgresql://db_admin:SuperSecretPass123!@prod-db.internal:5432/customer_db"
OPENAI_API_KEY="sk-proj-9876543210abcdef9876543210"
AWS_ACCESS_KEY="AKIAIOSFODNN7EXAMPLE"
SUPPORT_EMAIL="admin@securecompany.org"
        """.strip()
        raw_bytes = sample_code.encode("utf-8")
        doc_name = "prod.env"
    elif doc_upload is not None:
        raw_bytes = doc_upload.getvalue()
        doc_name = doc_upload.name

    if raw_bytes is not None:
        st.write(f"**Scanning File:** `{doc_name}` ({format_bytes(len(raw_bytes))})")
        doc_findings = scan_document(raw_bytes, doc_name)

        if not doc_findings:
            st.success("✅ Clean! No sensitive identifiers or secret tokens detected in this document.")
        else:
            findings_df = pd.DataFrame(doc_findings)
            secret_count = len(findings_df[findings_df["Category"] == "Authentication Secret"])
            pii_count = len(findings_df) - secret_count

            m1, m2, m3 = st.columns(3)
            m1.metric("Total Findings", len(findings_df))
            m2.metric("PII Elements Found", pii_count)
            m3.metric("🚨 Exposed Secrets / Tokens", secret_count)

            st.dataframe(findings_df, use_container_width=True)

            csv_report = findings_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "⬇️ Download Document Findings Report (CSV)",
                data=csv_report,
                file_name=f"document_findings_{doc_name}.csv",
                mime="text/csv"
            )

# ----------------------------------------------------
# MODE 3: PHOTOS & SCREENSHOTS (EXIF / OCR / REDACTION)
# ----------------------------------------------------
elif mode == "🖼️ Photos & Screenshots (EXIF / OCR / Redaction)":
    from PIL import Image
    from src.image_scanner import (
        extract_exif_metadata,
        strip_image_metadata,
        scan_image_ocr,
        redact_image_region,
        auto_redact_sensitive_regions
    )

    st.subheader("🖼️ Image Privacy Inspector & Redaction Engine")
    st.write(
        "Photos and screenshots frequently expose hidden privacy risks such as **GPS location coordinates**, "
        "device serial numbers, and sensitive text (credit card numbers, IDs, patient records). "
        "Analyze images, strip invasive EXIF metadata, and blackout sensitive regions."
    )

    img_file = st.file_uploader(
        "Upload a Photo or Screenshot",
        type=["png", "jpg", "jpeg", "webp"],
        help="Upload JPG/PNG images to inspect EXIF metadata, OCR text, and apply redaction."
    )

    if img_file is not None:
        pil_img = Image.open(BytesIO(img_file.getvalue()))
        st.write(f"**Image Dimensions:** {pil_img.size[0]} × {pil_img.size[1]} px | **Format:** {pil_img.format}")

        col_img1, col_img2 = st.columns(2)
        with col_img1:
            st.write("##### Original Image Preview:")
            st.image(pil_img, use_container_width=True)

        # 1. EXIF GPS Metadata Analysis
        exif_info = extract_exif_metadata(pil_img)
        with col_img2:
            st.write("##### 🛰️ EXIF & GPS Metadata Analysis:")
            if exif_info["has_gps"]:
                st.error("🚨 **High Privacy Risk: Embedded GPS Coordinates Detected!**")
                st.json(exif_info["gps_info"])
            else:
                st.success("✅ Clean: No embedded GPS coordinates found in this image.")

            if exif_info["raw_tags"]:
                st.info(f"Device Information: {exif_info['raw_tags'].get('device', 'None')}")

            # EXIF Strip Button
            if st.button("🧹 Strip All Metadata & GPS from Image", use_container_width=True):
                clean_img = strip_image_metadata(pil_img)
                out_buf = BytesIO()
                clean_img.save(out_buf, format="PNG")
                st.download_button(
                    "⬇️ Download Metadata-Free Image (PNG)",
                    data=out_buf.getvalue(),
                    file_name=f"sanitized_{img_file.name}.png",
                    mime="image/png",
                    use_container_width=True
                )

        # 2. OCR Text & PII Scan
        st.write("---")
        st.subheader("🔍 OCR Text & Screenshot Content Scan")
        ocr_findings, extracted_ocr_text, sensitive_boxes = scan_image_ocr(pil_img)

        with st.expander("Extracted OCR Text"):
            st.text(extracted_ocr_text)

        if ocr_findings:
            st.warning(f"Detected {len(ocr_findings)} sensitive text element(s) in this image:")
            st.dataframe(pd.DataFrame(ocr_findings), use_container_width=True)

            # 1-Click Auto Redact
            if sensitive_boxes and st.button("🛡️ 1-Click Auto-Blackout All Detected PII on Image", type="primary", use_container_width=True):
                auto_redacted = auto_redact_sensitive_regions(pil_img, sensitive_boxes)
                st.write("##### Automatically Protected Image Preview:")
                st.image(auto_redacted, use_container_width=True)

                a_buf = BytesIO()
                auto_redacted.save(a_buf, format="PNG")
                st.download_button(
                    "⬇️ Download Auto-Redacted Image (PNG)",
                    data=a_buf.getvalue(),
                    file_name=f"auto_redacted_{img_file.name}.png",
                    mime="image/png",
                    use_container_width=True
                )
        else:
            st.info("No pattern-matched sensitive text was detected via OCR.")

        # 3. Manual Image Region Redaction (Blackout)
        st.write("---")
        st.subheader("✂️ Manual Redaction (Coordinate Black-Out)")
        st.write("Specify custom pixel coordinates to black-out any additional regions (faces, logos, signatures):")
        
        w, h = pil_img.size
        rc1, rc2, rc3, rc4 = st.columns(4)
        left = rc1.number_input("Left (X1)", min_value=0, max_value=w, value=0)
        top = rc2.number_input("Top (Y1)", min_value=0, max_value=h, value=0)
        right = rc3.number_input("Right (X2)", min_value=0, max_value=w, value=min(200, w))
        bottom = rc4.number_input("Bottom (Y2)", min_value=0, max_value=h, value=min(100, h))

        if st.button("⬛ Apply Black-Out Redaction", type="primary"):
            redacted_pil = redact_image_region(pil_img, (left, top, right, bottom), color="black")
            st.write("##### Redacted Image Preview:")
            st.image(redacted_pil, use_container_width=True)

            r_buf = BytesIO()
            redacted_pil.save(r_buf, format="PNG")
            st.download_button(
                "⬇️ Download Redacted Image (PNG)",
                data=r_buf.getvalue(),
                file_name=f"redacted_{img_file.name}.png",
                mime="image/png"
            )

# ----------------------------------------------------
# MODE 4: LIVE DATABASE INSPECTOR (SQLite / SQL)
# ----------------------------------------------------
elif mode == "🗄️ Relational Databases (SQLite / SQL)":
    st.subheader("🗄️ Read-Only Relational Database Inspector")
    st.write(
        "Inspect database schemas and tables in strictly read-only mode. "
        "Profiles column definitions, uniqueness, and detects PII without modifying underlying source tables."
    )

    db_option = st.radio(
        "Database Source:",
        ["Inspect Pre-Configured Hospital Database (`sample_hospital.db`)", "Upload Local SQLite Database (`.db` / `.sqlite`)"],
        horizontal=True
    )

    target_db_path = None
    if db_option == "Inspect Pre-Configured Hospital Database (`sample_hospital.db`)":
        sample_db = os.path.join(os.path.dirname(__file__), "sample_data", "sample_hospital.db")
        if os.path.exists(sample_db):
            target_db_path = sample_db
    else:
        uploaded_db = st.file_uploader("Upload SQLite database file", type=["db", "sqlite", "sqlite3"])
        if uploaded_db is not None:
            # Save safely to temp file for read-only inspection
            temp_db = os.path.join(os.path.dirname(__file__), "sample_data", f"temp_{uploaded_db.name}")
            with open(temp_db, "wb") as f:
                f.write(uploaded_db.getvalue())
            target_db_path = temp_db

    if target_db_path:
        st.write(f"**Target Database:** `{target_db_path.split(os.sep)[-1]}`")
        db_results = inspect_sqlite_database(target_db_path)

        col1, col2 = st.columns(2)
        col1.metric("Tables Scanned", db_results["summary"]["total_tables"])
        col2.metric("Sensitive Fields Detected", db_results["summary"]["total_sensitive_columns"])

        st.write("### Database Schema & Sampling:")
        for t in db_results["tables"]:
            with st.expander(f"Table: `{t['table_name']}` ({t['total_rows']:,} rows, {len(t['columns'])} columns)"):
                st.write(f"**Columns:** {', '.join(t['columns'])}")
                st.write(f"**Sensitive Columns Flagged:** {t['sensitive_columns_found']}")
                st.dataframe(t["sample_preview"], use_container_width=True)

        if db_results["findings"]:
            st.write("### Database Privacy Findings:")
            findings_df = pd.DataFrame(db_results["findings"])
            st.dataframe(findings_df, use_container_width=True)

            csv_rep = findings_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "⬇️ Download Database Audit Report (CSV)",
                data=csv_rep,
                file_name=f"database_findings_{db_results['summary']['database_name']}.csv",
                mime="text/csv"
            )

# ----------------------------------------------------
# MODE 5: WEB LINKS, TRACKERS & ATTACK SCRIPT INSPECTOR
# ----------------------------------------------------
elif mode == "🌐 Web Links, Trackers & Attack Script Inspector":
    from src.link_scanner import scan_live_web_link

    st.subheader("🌐 Web Link Privacy, Tracker & Attack Script Inspector")
    st.write(
        "Analyze external URLs and web pages before clicking or sharing them. "
        "Uncovers cross-site ad tracking parameters (`fbclid`, `gclid`), third-party analytics pixels, "
        "fingerprinting probes, and malicious scripts (keyloggers, clipboard hijacking, cryptominers)."
    )

    sample_urls = [
        "https://example.com?utm_source=newsletter&fbclid=IwAR2XYZ9876543210&gclid=Cj0KCQj12345",
        "https://httpbin.org/get",
        "https://news.ycombinator.com"
    ]
    target_link = st.text_input("Enter Web Link (URL) to Audit:", value=sample_urls[0])

    if st.button("🔍 Audit Link & Scan For Trackers / Scripts", type="primary"):
        if target_link.startswith("http://") or target_link.startswith("https://"):
            with st.spinner("Connecting and auditing link DOM, scripts, headers, and parameters..."):
                link_report = scan_live_web_link(target_link)

            # Overview metrics
            l_col1, l_col2, l_col3, l_col4 = st.columns(4)
            l_col1.metric("Privacy Threat Score", f"{link_report['risk_score']}/100", delta=link_report["risk_level"], delta_color="inverse")
            l_col2.metric("URL Tracking Tokens", len(link_report["url_trackers"]))
            l_col3.metric("3rd-Party Trackers Found", len(link_report["third_party_trackers"]))
            l_col4.metric("Suspicious Script Probes", len(link_report["suspicious_scripts"]))

            # Tactical Cyber Threat Meter Gauge
            link_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=link_report['risk_score'],
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "WEB LINK THREAT & TRACKING INDEX", 'font': {'color': '#94a3b8', 'size': 14}},
                number={'font': {'color': '#38bdf8', 'size': 38, 'family': 'JetBrains Mono'}},
                gauge={
                    'axis': {'range': [0, 100], 'tickcolor': '#475569'},
                    'bar': {'color': "#00f2fe"},
                    'bgcolor': "#0b132b",
                    'borderwidth': 1,
                    'bordercolor': "#1e293b",
                    'steps': [
                        {'range': [0, 35], 'color': "rgba(16, 185, 129, 0.25)"},
                        {'range': [35, 65], 'color': "rgba(245, 158, 11, 0.25)"},
                        {'range': [65, 100], 'color': "rgba(239, 68, 68, 0.35)"},
                    ],
                    'threshold': {
                        'line': {'color': "#ef4444", 'width': 3},
                        'thickness': 0.8,
                        'value': 65
                    }
                }
            ))
            link_gauge.update_layout(
                paper_bgcolor="#091222",
                plot_bgcolor="#091222",
                height=240,
                margin=dict(l=20, r=20, t=30, b=15)
            )
            st.plotly_chart(link_gauge, use_container_width=True)

            # 1. URL Parameter Tracking
            if link_report["url_trackers"]:
                st.write("### 🏷️ Invasive URL Tracking Parameters Detected:")
                st.dataframe(pd.DataFrame(link_report["url_trackers"]), use_container_width=True)

            # 2. Third-Party Telemetry & Ad Trackers
            if link_report["third_party_trackers"]:
                st.write("### 👁️ Third-Party Trackers & Session Replay Scripts:")
                st.dataframe(pd.DataFrame(link_report["third_party_trackers"]), use_container_width=True)

            # 3. Malicious / Attack Scripts
            if link_report["suspicious_scripts"]:
                st.error("### 🚨 Attack Script & Invasive Probe Warnings:")
                st.dataframe(pd.DataFrame(link_report["suspicious_scripts"]), use_container_width=True)

            # 4. Security & Privacy Headers
            with st.expander("🛡️ HTTP Security & Privacy Header Posture"):
                st.json(link_report["security_headers"])
                if link_report["missing_privacy_headers"]:
                    st.warning("Missing Policies: " + ", ".join(link_report["missing_privacy_headers"]))

            # Download Findings Report
            all_link_findings = link_report["url_trackers"] + link_report["third_party_trackers"] + link_report["suspicious_scripts"]
            if all_link_findings:
                link_csv = pd.DataFrame(all_link_findings).to_csv(index=False).encode("utf-8")
                st.download_button(
                    "⬇️ Download Link Privacy Audit Report (CSV)",
                    data=link_csv,
                    file_name="link_privacy_report.csv",
                    mime="text/csv"
                )
        else:
            st.error("Please enter a valid URL starting with http:// or https://")

# ----------------------------------------------------
# MODE 6: GIT REPOSITORIES & PROJECT FOLDERS
# ----------------------------------------------------
elif mode == "💻 Git Repositories & Project Folders":
    from src.repo_scanner import scan_local_git_repo

    st.subheader("💻 Local Git Repository & Codebase Privacy Scanner")
    st.write(
        "Scan local codebases, project directories, and Git worktrees recursively. "
        "Locates hardcoded credentials, `.env` leaks, private keys, database connection strings, and PII "
        "with file paths and line numbers so you can remediate them before committing."
    )

    default_repo = os.path.abspath(os.path.dirname(__file__))
    target_repo = st.text_input("Enter Repository / Folder Path to Scan:", value=default_repo)
    max_scan_files = st.slider("Max Files to Inspect:", min_value=10, max_value=500, value=150)

    if st.button("🚀 Run Deep Repository Scan", type="primary"):
        if os.path.exists(target_repo):
            with st.spinner("Scanning repository files..."):
                repo_findings = scan_local_git_repo(target_repo, max_files=max_scan_files)

            if not repo_findings:
                st.success("✅ Clean! No exposed credentials or unencrypted secrets detected in this repository.")
            else:
                st.error(f"🚨 Flagged {len(repo_findings)} security/privacy risk(s) in repository files:")
                r_df = pd.DataFrame(repo_findings)

                c1, c2 = st.columns(2)
                crit_count = len(r_df[r_df["Severity"] == "Critical"])
                c1.metric("Critical Exposed Secrets", crit_count)
                c2.metric("High PII Disclosures", len(r_df) - crit_count)

                st.dataframe(r_df, use_container_width=True)

                r_csv = r_df.to_csv(index=False).encode("utf-8")
                st.download_button(
                    "⬇️ Download Repository Audit Report (CSV)",
                    data=r_csv,
                    file_name="repository_privacy_audit.csv",
                    mime="text/csv",
                    use_container_width=True
                )
        else:
            st.error("Specified path does not exist. Please provide a valid directory.")

# ----------------------------------------------------
# MODE 6: SYNTHETIC DATA GENERATOR
# ----------------------------------------------------
elif mode == "🧬 Synthetic Data Generator":
    st.subheader("🧬 Privacy-Preserving Synthetic Data Generator")
    st.write(
        "Generate realistic synthetic datasets modeled on your data. "
        "Preserves marginal distributions, numerical means, covariances, and categorical frequency representations "
        "while eliminating individual record identities."
    )

    synth_sample = st.button("Use Sample Benchmark Dataset", use_container_width=False)
    synth_file = st.file_uploader("Or Upload Reference CSV/Excel", type=["csv", "xlsx"])

    ref_df = None
    if synth_sample:
        s_path = os.path.join(os.path.dirname(__file__), "sample_data", "sample_dataset.csv")
        if os.path.exists(s_path):
            ref_df = pd.read_csv(s_path)
            st.session_state["synth_ref"] = ref_df
    elif synth_file is not None:
        ref_df = load_dataset(synth_file.getvalue(), synth_file.name)
        st.session_state["synth_ref"] = ref_df
    elif "synth_ref" in st.session_state:
        ref_df = st.session_state["synth_ref"]

    if ref_df is not None:
        st.write("##### Reference Dataset Preview:")
        st.dataframe(ref_df.head(5), use_container_width=True)

        sc1, sc2 = st.columns(2)
        n_rows = sc1.number_input("Number of Synthetic Records to Generate", min_value=5, max_value=10000, value=len(ref_df))
        noise_f = sc2.slider("Distribution Smoothing Factor", min_value=0.01, max_value=0.20, value=0.05)

        if st.button("🚀 Generate Synthetic Dataset", type="primary"):
            synth_result = generate_synthetic_dataset(ref_df, num_samples=int(n_rows), noise_factor=noise_f)
            st.success(f"Generated {len(synth_result):,} synthetic records.")
            
            st.write("##### Synthetic Dataset Preview:")
            st.dataframe(synth_result.head(10), use_container_width=True)

            synth_csv = synth_result.to_csv(index=False).encode("utf-8")
            st.download_button(
                "⬇️ Download Synthetic Dataset (CSV)",
                data=synth_csv,
                file_name="synthetic_dataset.csv",
                mime="text/csv"
            )

# ----------------------------------------------------
# MODE 6: AUDIO/VIDEO TRANSCRIPTS & SUBTITLES (.SRT / .VTT)
# ----------------------------------------------------
elif mode == "🎙️ Audio/Video Transcripts & Subtitles (.srt/.vtt)":
    from src.media_scanner import scan_media_transcript

    st.subheader("🎙️ Spoken Media Privacy & Subtitle Scanner")
    st.write(
        "Spoken dialogue in recordings, Zoom meetings, support calls, and videos frequently contains sensitive "
        "PII (names, phone numbers, addresses, account details). "
        "Upload subtitles or transcripts (**`.srt`**, **`.vtt`**, **`.txt`**) to pinpoint exact spoken timestamps of sensitive data."
    )

    sample_media = st.button("Load Sample Support Call Transcript (.srt)")
    media_upload = st.file_uploader("Upload Subtitle or Transcript file", type=["srt", "vtt", "txt"])

    raw_media_bytes = None
    media_name = ""

    if sample_media:
        sample_srt = """
1
00:00:01,200 --> 00:00:04,500
Support: Thank you for calling customer care. May I have your full name and email?

2
00:00:05,000 --> 00:00:09,800
Caller: Yes, my name is Arthur Dent and my email address is arthur.dent@galacticsurvey.org.

3
00:00:10,200 --> 00:00:14,000
Support: And can you verify your primary phone number on the account?

4
00:00:14,500 --> 00:00:18,900
Caller: Sure, it is +1-555-424-2424 and my SSN last digits are 123-45-6789.
        """.strip()
        raw_media_bytes = sample_srt.encode("utf-8")
        media_name = "support_call_recording.srt"
    elif media_upload is not None:
        raw_media_bytes = media_upload.getvalue()
        media_name = media_upload.name

    if raw_media_bytes is not None:
        st.write(f"**Scanning Spoken Media:** `{media_name}`")
        media_findings = scan_media_transcript(raw_media_bytes, media_name)

        if not media_findings:
            st.success("✅ Clean! No sensitive identifiers detected in this spoken transcript.")
        else:
            st.warning(f"Detected {len(media_findings)} spoken sensitive elements with timestamp references:")
            m_df = pd.DataFrame(media_findings)
            st.dataframe(m_df, use_container_width=True)

            csv_rep = m_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "⬇️ Download Spoken Media Privacy Findings (CSV)",
                data=csv_rep,
                file_name=f"spoken_media_findings_{media_name}.csv",
                mime="text/csv"
            )

# ----------------------------------------------------
# MODE 7: SCAN AUDIT HISTORY & RECURRING LOGS
# ----------------------------------------------------
else:
    from src.audit_history import get_scan_history

    st.subheader("📜 Scan Audit History & Compliance Trail")
    st.write(
        "Auditable record of all privacy scans performed during this and past sessions. "
        "Enables regression tracking, compliance monitoring, and historical security verification."
    )

    history = get_scan_history()
    if not history:
        st.info("No scans recorded yet. Perform scans across Tabular, Documents, Images, or Databases to build the audit trail.")
    else:
        st.metric("Total Scans Recorded", len(history))
        h_df = pd.DataFrame(history)
        st.dataframe(h_df, use_container_width=True)

        st.download_button(
            "⬇️ Export Complete Audit Trail (JSON)",
            data=json.dumps(history, indent=2).encode("utf-8"),
            file_name="complete_audit_trail.json",
            mime="application/json"
        )

