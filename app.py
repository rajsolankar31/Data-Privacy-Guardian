from src import (
    detect_sensitive_data,
    apply_protection,
    calculate_risk_assessment,
    evaluate_utility,
    generate_markdown_report,
)
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from io import BytesIO

st.set_page_config(
    page_title="Data Privacy Guardian",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom header styling
st.markdown("""
<style>
    .metric-card {
        background-color: #f8f9fa;
        border-radius: 8px;
        padding: 12px;
        border-left: 5px solid #2b5c8f;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ AI-Powered Data Privacy Guardian")
st.caption("A local-first data privacy analysis, risk assessment, and data protection platform.")

st.info(
    "🔒 **Local-first Security Guarantee:** All processing occurs completely inside your local Python session. "
    "Zero data is sent to external cloud APIs or third parties."
)

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


# Sidebar Navigation & Sample Data Loader
st.sidebar.header("📁 Dataset Source")
load_sample = st.sidebar.button("Load Sample Medical/Customer Dataset", use_container_width=True)

uploaded_file = st.sidebar.file_uploader(
    "Upload CSV or Excel file",
    type=["csv", "xlsx"],
    help="Upload your dataset to profile sensitive data and test transformations."
)

active_df = None
file_name = ""
file_size_str = ""

if load_sample:
    import os
    sample_path = os.path.join(os.path.dirname(__file__), "sample_data", "sample_dataset.csv")
    if os.path.exists(sample_path):
        active_df = pd.read_csv(sample_path)
        file_name = "sample_dataset.csv"
        file_size_str = format_bytes(os.path.getsize(sample_path))
        st.session_state["active_df"] = active_df
        st.session_state["file_name"] = file_name
        st.session_state["file_size_str"] = file_size_str

if uploaded_file is not None:
    file_bytes = uploaded_file.getvalue()
    active_df = load_dataset(file_bytes, uploaded_file.name)
    file_name = uploaded_file.name
    file_size_str = format_bytes(len(file_bytes))
    st.session_state["active_df"] = active_df
    st.session_state["file_name"] = file_name
    st.session_state["file_size_str"] = file_size_str
elif "active_df" in st.session_state:
    active_df = st.session_state["active_df"]
    file_name = st.session_state["file_name"]
    file_size_str = st.session_state["file_size_str"]

if active_df is not None:
    df = active_df.copy()

    if df.empty:
        st.warning("The selected dataset contains no data rows or columns.")
    else:
        # 1. Dataset Overview
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

            st.dataframe(
                findings,
                use_container_width=True,
                column_config={
                    "Confidence": st.column_config.TextColumn(
                        "Confidence Level",
                    )
                }
            )

        # 3. Privacy Protection Configuration
        st.subheader("🛡️ 3. Privacy Protection Configuration")
        st.write("Configure targeted transformations per column to protect sensitive data while preserving research utility.")

        detected_cols = findings["Column"].unique().tolist() if not findings.empty else []
        all_cols = list(df.columns)

        col_selection = st.multiselect(
            "Select columns to protect:",
            options=all_cols,
            default=[c for c in detected_cols if c in all_cols],
            help="Select columns to apply redaction, masking, generalization, pseudonymization, or removal."
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
                    
                    # Choose default based on role
                    default_idx = 0
                    if role_guess == "Direct Identifier":
                        default_idx = 1 # Mask or Redact
                    elif role_guess == "Quasi-Identifier":
                        default_idx = 3 # Generalize
                    elif role_guess == "Sensitive Attribute":
                        default_idx = 3 # Generalize or Redact

                    method = st.selectbox(
                        f"Action for {c}",
                        options=["Redact", "Mask", "Pseudonymize", "Generalize", "Remove"],
                        index=default_idx,
                        key=f"method_{c}"
                    )

                    params = {}
                    if method == "Generalize":
                        step = st.number_input(f"Bin interval / step for {c}", min_value=1, max_value=100000, value=10, key=f"step_{c}")
                        params["step"] = float(step)
                    elif method == "Mask":
                        keep = st.slider(f"Unmasked edge chars for {c}", 0, 4, 1, key=f"mask_{c}")
                        params["keep_first"] = keep
                        params["keep_last"] = keep
                    elif method == "Pseudonymize":
                        params["salt"] = "guardian_secret_salt"

                    column_actions[c] = {"method": method, "params": params}

        # Apply transformations
        protected_df = apply_protection(df, column_actions)

        # 4. Protected Data Preview
        with st.expander("👁️ 4. Protected Dataset Preview", expanded=True):
            st.dataframe(protected_df.head(10), use_container_width=True)

        # 5. Privacy Risk Assessment & k-Anonymity
        st.subheader("⚖️ 5. Privacy Risk & Re-Identification Assessment")
        risk_data = calculate_risk_assessment(df, protected_df, findings, column_actions)

        r_col1, r_col2, r_col3, r_col4 = st.columns(4)
        r_col1.metric("Overall Risk Score", f"{risk_data['overall_risk_score']}/100", delta=risk_data["risk_level"], delta_color="inverse")
        r_col2.metric("Singling-Out Risk", f"{risk_data['reidentification_risk']}%", help="Percentage of records uniquely distinguishable via quasi-identifiers.")
        r_col3.metric("Min k-Anonymity", f"k = {risk_data['k_anonymity_estimate']}", help="Smallest equivalence group size across quasi-identifiers.")
        r_col4.metric("Detection Coverage", f"{risk_data['coverage_percentage']}%")

        # Visual Risk Gauge
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=risk_data['overall_risk_score'],
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Privacy Risk Meter (Lower is Safer)"},
            gauge={
                'axis': {'range': [0, 100]},
                'bar': {'color': "#2b5c8f"},
                'steps': [
                    {'range': [0, 35], 'color': "#d4edda"},
                    {'range': [35, 70], 'color': "#fff3cd"},
                    {'range': [70, 100], 'color': "#f8d7da"},
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 70
                }
            }
        ))
        fig_gauge.update_layout(height=260, margin=dict(l=20, r=20, t=40, b=20))
        st.plotly_chart(fig_gauge, use_container_width=True)

        st.markdown("**🛡️ Risk Mitigation Recommendations:**")
        for rec in risk_data["recommendations"]:
            st.info(f"👉 {rec}")

        # 6. Data Utility & Statistical Preservation
        st.subheader("📈 6. Analytical Utility & Trade-Off Assessment")
        utility_data = evaluate_utility(df, protected_df)

        u_col1, u_col2, u_col3 = st.columns(3)
        u_col1.metric("Overall Utility Score", f"{utility_data['overall_utility_score']}%", help="Composite score reflecting column retention, statistical means, and categorical diversity.")
        u_col2.metric("Row Retention", f"{utility_data['rows_retained_pct']}%")
        u_col3.metric("Column Retention", f"{utility_data['columns_retained_pct']}%")

        # Distribution / Numeric Comparison
        if not utility_data["numeric_metrics"].empty:
            st.write("##### Numerical Distribution Preservation:")
            st.dataframe(utility_data["numeric_metrics"], use_container_width=True)

        if not utility_data["categorical_metrics"].empty:
            st.write("##### Categorical Diversity Preservation:")
            st.dataframe(utility_data["categorical_metrics"], use_container_width=True)

        # 7. Export & Compliance Reporting
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

        with st.expander("📜 View Audit Report Preview"):
            st.markdown(report_md)

else:
    st.info("👈 Upload a dataset via the sidebar or click **'Load Sample Medical/Customer Dataset'** to begin.")
