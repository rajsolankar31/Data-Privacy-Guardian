# 🛡️ AI-Powered Data Privacy Guardian

### A Local-First, Multi-Format Data Privacy Analysis, Risk Assessment, and Protection Platform

**Discover sensitive information. Understand privacy risks. Protect data. Validate results.**

[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Interface-Streamlit-red.svg)](https://streamlit.io/)
[![Privacy](https://img.shields.io/badge/Focus-Data%20Privacy-green.svg)](#security-and-privacy-principles)
[![Architecture](https://img.shields.io/badge/Architecture-Local--First-purple.svg)](#architecture)
[![Tests](https://img.shields.io/badge/Tests-13%20Passed-brightgreen.svg)](#testing-and-quality-assurance)

---

## 📌 1. Project Overview

**AI-Powered Data Privacy Guardian** is a production-grade, local-first privacy analysis and protection platform designed to identify, assess, and protect sensitive information across:
- **Tabular Datasets & Spreadsheets:** CSV, XLSX, XLS.
- **Unstructured Documents:** PDF, Word (`.docx`), Plain Text (`.txt`), Markdown (`.md`).
- **Configuration & Source Code:** JSON, YAML, Python (`.py`), `.env` files, and server logs.
- **Relational Databases:** SQLite databases and schemas (read-only introspection).
- **Privacy-Enhancing Technologies (PETs):** Differential Privacy ($\varepsilon$-Laplace noise) and Multivariate Synthetic Data Generation.

The platform operates **100% locally** in the running Python session without sending raw data to external cloud APIs.

---

## 🚀 2. The Complete Privacy Workflow

```
   INPUT SOURCES
┌───────────────────────┐
│ • CSV / Excel Spreadsheets
│ • PDF / DOCX Documents│ ───►  [Format Ingestion & Profiling]
│ • Source Code & .env  │
│ • SQLite Databases    │
└───────────────────────┘
                                       │
                                       ▼
                        [Sensitive Information Discovery]
                        • Direct Identifiers (PII)
                        • Quasi-Identifiers (Age, ZIP, Gender)
                        • Sensitive Attributes (Salaries, Diagnoses)
                        • Authentication Secrets (API Keys, Tokens, DB URIs)
                                       │
                                       ▼
                        [Privacy Risk & Linkage Engine]
                        • Minimum k-Anonymity Class Estimation
                        • Distinct l-Diversity Evaluation
                        • Singling-Out Exposure Probability
                        • Visual Risk Meter Gauge (0 - 100)
                                       │
                                       ▼
                        [Transformation & Protection Suite]
                        • Redaction ([REDACTED])
                        • Partial Masking (a***@domain.com, 4***-11)
                        • Range Generalization (e.g., 29 -> "20 - 29")
                        • Salted SHA-256 Pseudonymization
                        • Differential Privacy (Laplace Mechanism with ε budget)
                        • Column Removal / Suppression
                                       │
                                       ▼
                        [Utility Assessment & Validation]
                        • Completeness & Retention Metrics
                        • Mean & Variance Statistical Retention
                        • Categorical Diversity & Frequency Analysis
                                       │
                                       ▼
                        [Audit Reporting & Data Export]
                        • Downloadable Clean/Protected Datasets (CSV)
                        • Downloadable Synthetic Datasets (CSV)
                        • Downloadable Privacy Audit Reports (Markdown/CSV)
```

---

## ✨ 3. Core Features & Capabilities

### 🔍 A. Multi-Format Sensitive Discovery
- **Heuristics & Dictionaries:** Semantic column classifications across Emails, Phone Numbers, Names, Government IDs (SSN, Aadhaar, PAN, Passports), Financial Attributes, Demographics, and Health Information.
- **Pattern Matching (Regex):** Robust value inspection across structured cells and multi-line unstructured text.
- **Secret & Token Detection:** Identifies API keys, Bearer tokens, AWS access keys, private key headers (`BEGIN PRIVATE KEY`), and database connection strings (`postgresql://...`, `mongodb://...`).
- **Evidence Masking:** Automatically sanitizes findings (e.g. `sec***********345`) to prevent accidental disclosure in reports.

### 🛡️ B. Protection Suite & Privacy-Enhancing Technologies (PETs)
- **Redaction:** Swaps sensitive values for `[REDACTED]` while preserving missingness structures.
- **Masking:** Configurable character masking preserving domains or edge values.
- **Generalization / Binning:** Replaces exact numbers (age, income) with interval brackets and truncates location precision.
- **Pseudonymization:** Deterministic salted cryptographic hashing (`PSEUDO_<hash>`) guaranteeing referential integrity across analytical joins.
- **Differential Privacy (DP):** Adds calibrated Laplace noise parameterized by an $\varepsilon$ privacy budget ($0.1 \le \varepsilon \le 5.0$).
- **Synthetic Data Generation:** Generates parametric multivariate synthetic records modeling numerical Gaussian parameters and empirical categorical distributions while breaking record-level identity linkages.

### ⚖️ C. Explainable Risk & Re-Identification Engine
- **$k$-Anonymity Estimation:** Computes the minimum equivalence class size across quasi-identifiers.
- **$l$-Diversity Evaluation:** Assesses distinct sensitive values within quasi-identifier equivalence groups.
- **Singling-Out Risk:** Quantifies the proportion of uniquely identifiable rows.
- **Explainable Guidance:** Generates plain-English mitigation steps tied directly to detected risk vectors.

### 📈 D. Analytical Utility Preservation
- Measures row/column retention percentages.
- Tracks statistical drift: Original vs. Protected Mean, Standard Deviation, and Mean Relative Error.
- Evaluates categorical diversity and unique cardinality retention.

### 🗄️ E. Read-Only Relational Database Inspection
- Safely connects to SQLite databases in `mode=ro` (read-only).
- Introspects schemas, tables, and column metadata.
- Samples and profiles records with bounded limits without writing to or modifying tables.

---

## 🛠️ 4. Project Structure

```text
data-privacy-guardian/
│
├── app.py                      # Master Streamlit application (Tabular, Docs, DBs, Synthetic)
├── requirements.txt            # Project dependencies
├── README.md                   # Comprehensive platform documentation
├── .gitignore                  # Git exclusions (.venv, caches, temp files)
├── .env.example                # Configuration environment variables template
│
├── src/
│   ├── __init__.py             # Public package exports
│   ├── sensitive_detector.py   # Column heuristics, regex patterns, PII roles
│   ├── document_scanner.py     # PDF, DOCX, TXT, JSON, code & secret scanner
│   ├── protection.py           # Redaction, masking, binning, pseudonymization
│   ├── privacy_risk.py         # Risk scoring, k-anonymity, l-diversity
│   ├── utility_assessment.py   # Statistical drift, distributions & diversity
│   ├── advanced_pets.py        # Differential privacy (Laplace) & Synthetic generator
│   ├── reporting.py            # Audit report compiler
│   │
│   └── connectors/
│       ├── __init__.py
│       └── sqlite_connector.py # Safe read-only SQLite database inspector
│
├── tests/
│   ├── test_sensitive_detector.py  # Detector heuristics and patterns
│   ├── test_protection.py          # Protection transformations
│   ├── test_privacy_risk.py        # Risk scoring & utility evaluation
│   ├── test_document_scanner.py    # Multi-format document & secret parser
│   └── test_advanced_features.py   # SQLite inspector & PETs test suite
│
├── sample_data/
│   ├── sample_dataset.csv          # Clinical / customer benchmark dataset
│   ├── sample_hospital.db          # Relational SQLite database with patient/staff schemas
│   └── generate_db.py              # Generator script for test databases
│
└── reports/                        # Exported audit reports directory
```

---

## 💻 5. Quickstart & Installation

### Prerequisites
- Python 3.12+
- Windows, macOS, or Linux
- Modern web browser

### 1. Clone the Repository
```bash
git clone https://github.com/rajsolankar31/Data-Privacy-Guardian.git
cd Data-Privacy-Guardian
```

### 2. Set Up Virtual Environment
```bash
# On Windows PowerShell:
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# On macOS/Linux:
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Run the Application
```bash
streamlit run app.py
```
Open **`http://localhost:8501`** in your browser.

---

## 🧪 6. Testing and Quality Assurance

Run the complete automated test suite using `pytest`:
```bash
pytest tests/
```
**Test Coverage:**
- 13/13 passing tests across:
  - Heuristic column classification & pattern detection
  - Redaction, Masking, Generalization, Pseudonymization
  - Multi-format text extraction (PDF, Word, Code)
  - Secret & credential detection with evidence masking
  - Read-only SQLite database inspection & schema extraction
  - Differential Privacy Laplace noise mechanics
  - Synthetic dataset shape and distribution validation

---

## 🔒 7. Security and Privacy Principles

1. **Local-First Processing:** Uploaded files and databases are processed in local memory. No third-party cloud AI APIs are called.
2. **Least-Privilege Database Access:** Relational database connections are enforced in read-only mode (`mode=ro`).
3. **Data Minimization & Safe Evidence:** Detected credentials and raw PII values are masked in findings tables and exported reports.
4. **No Absolute Privacy Claims:** Transforming data reduces specific disclosure risks; it does not guarantee legal compliance or complete anonymity. Always review residual risk metrics before sharing data.

---

## 📄 8. License
This project is licensed under the **MIT License**.
