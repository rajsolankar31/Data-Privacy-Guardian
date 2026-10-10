# 🛡️ AI-Powered Data Privacy Guardian

A local-first data privacy analysis, risk assessment, and data protection platform.

---
*LIVE LINK: https://data-privacy-guardian-rajsolankar31.streamlit.app/

## 📌 Overview

**AI-Powered Data Privacy Guardian** is designed to help analysts, developers, students, and organizations inspect datasets for sensitive and identifying information, assess privacy vulnerabilities, apply privacy-preserving transformations, and evaluate analytical utility preservation without relying on third-party cloud APIs.

---

## ✨ Features

- **🔍 Intelligent Sensitive Data Discovery:** Heuristic column classifications and value-level regex pattern detection across PII, Financial records, Healthcare info, Government IDs, and Demographics. Differentiates:
  - *Direct Identifiers* (Names, Emails, Phones, Government IDs)
  - *Quasi-Identifiers* (Age, ZIP, Gender, Location)
  - *Sensitive Attributes* (Diagnoses, Salaries)
- **🛡️ Multiple Protection Mechanisms:**
  - **Redaction:** Replaces sensitive values with `[REDACTED]` while retaining missingness structures.
  - **Masking:** Mask characters retaining edge values or email domains (e.g. `a*****n@example.com`, `4***********11`).
  - **Generalization / Binning:** Numeric range grouping (e.g. age `29` $\to$ `20 - 29`) or postal code truncation.
  - **Pseudonymization:** Deterministic, salted SHA-256 cryptographic tokenization.
  - **Column Removal:** Completely drops selected fields.
- **⚖️ Privacy Risk & Re-Identification Engine:**
  - Evaluates singling-out / re-identification risk across quasi-identifiers.
  - Estimates minimum $k$-Anonymity group size.
  - Produces an explainable 0–100 privacy risk score with visual gauge and mitigation tips.
- **📈 Analytical Utility & Trade-Off Assessment:**
  - Measures row & column completeness, distribution mean/variance retention, and categorical diversity preservation.
- **📄 Audit Reporting & Export:**
  - Generates downloadable compliance audit reports in Markdown.
  - Exports protected datasets directly in CSV format.
- **🔒 Local-First Architecture:** Complete offline processing without external API dependencies.

---

## 🚀 Quickstart & Installation

### 1. Clone the repository
```bash
git clone https://github.com/rajsolankar31/Data-Privacy-Guardian.git
cd Data-Privacy-Guardian
```

### 2. Set up virtual environment
```bash
python -m venv .venv
# On Windows:
.\.venv\Scripts\Activate.ps1
# On macOS/Linux:
source .venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Streamlit application
```bash
streamlit run app.py
```

Open `http://localhost:8501` in your browser.

---

## 🧪 Running Tests

Execute automated unit tests with `pytest`:
```bash
pytest tests/
```

---

## 📂 Project Structure

```text
data-privacy-guardian/
│
├── app.py                      # Main Streamlit application
├── requirements.txt            # Project dependencies
├── README.md                   # Documentation
├── .gitignore
│
├── src/
│   ├── __init__.py
│   ├── sensitive_detector.py   # Pattern & column discovery
│   ├── protection.py           # Redaction, masking, generalization, pseudonymization
│   ├── privacy_risk.py         # Risk scoring & k-anonymity estimation
│   ├── utility_assessment.py   # Distribution & diversity retention
│   └── reporting.py            # Audit report generation
│
├── tests/
│   ├── test_sensitive_detector.py
│   ├── test_protection.py
│   └── test_privacy_risk.py
│
├── sample_data/
│   └── sample_dataset.csv      # Synthetic benchmark dataset
│
└── reports/
```

---

## ⚖️ License
MIT License.
