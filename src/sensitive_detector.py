import re
import pandas as pd
import numpy as np

# Column categorization dictionaries with expanded heuristics
COLUMN_CATEGORIES = {
    "Email": ["email", "e_mail", "mail_id", "email_address"],
    "Phone Number": ["phone", "mobile", "telephone", "contact_no", "contact_number", "cell"],
    "Name": ["name", "full_name", "first_name", "last_name", "fname", "lname", "customer_name", "patient_name", "employee_name"],
    "Financial Information": [
        "salary", "income", "bank_account", "account_number", "acc_no", "credit_card",
        "card_number", "cvv", "payment", "iban", "swift", "routing_number", "balance"
    ],
    "Government ID": [
        "aadhaar", "aadhar", "passport", "national_id", "tax_id", "pan_number", "ssn",
        "social_security", "voter_id", "driving_license", "dl_number"
    ],
    "Location": [
        "address", "street", "postal_code", "zip_code", "zip", "pincode", "latitude", "lat",
        "longitude", "long", "lon", "city", "state", "country"
    ],
    "Health Information": [
        "diagnosis", "medical", "health", "patient", "prescription", "blood_group",
        "disease", "condition", "treatment", "doctor"
    ],
    "Demographics": [
        "age", "gender", "sex", "race", "ethnicity", "religion", "marital_status", "dob", "birth_date"
    ],
}

# Regex patterns for value-level inspection
PATTERNS = {
    "Email": re.compile(
        r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    ),
    "Phone Number": re.compile(
        r"^(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}$"
    ),
    "Credit Card": re.compile(
        r"^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})$"
    ),
    "SSN": re.compile(
        r"^\d{3}-\d{2}-\d{4}$"
    ),
    "Indian PAN": re.compile(
        r"^[A-Z]{5}[0-9]{4}[A-Z]{1}$"
    ),
    "Indian Aadhaar": re.compile(
        r"^\d{4}\s?\d{4}\s?\d{4}$"
    ),
    "IPv4 Address": re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    ),
}

# Classification of categories into Privacy Roles
CATEGORY_ROLE_MAP = {
    "Email": "Direct Identifier",
    "Phone Number": "Direct Identifier",
    "Name": "Direct Identifier",
    "Government ID": "Direct Identifier",
    "Credit Card": "Direct Identifier",
    "SSN": "Direct Identifier",
    "Indian PAN": "Direct Identifier",
    "Indian Aadhaar": "Direct Identifier",
    "IPv4 Address": "Direct Identifier",
    "Location": "Quasi-Identifier",
    "Demographics": "Quasi-Identifier",
    "Financial Information": "Sensitive Attribute",
    "Health Information": "Sensitive Attribute",
}


def classify_column(column_name: str):
    """Classifies a column by its name heuristics."""
    normalized = str(column_name).lower().strip()
    normalized = re.sub(r"[^a-z0-9]+", "_", normalized)

    for category, keywords in COLUMN_CATEGORIES.items():
        for keyword in keywords:
            # Check exact match or tokenized substring
            tokens = normalized.split("_")
            if keyword in tokens or normalized == keyword:
                return category
    return None


def detect_sensitive_data(df: pd.DataFrame, sample_size: int = 500) -> pd.DataFrame:
    """
    Analyzes dataframe columns and values to detect sensitive information.
    Differentiates between Direct Identifiers, Quasi-Identifiers, and Sensitive Attributes.
    """
    findings = []
    
    if df.empty:
        return pd.DataFrame(columns=[
            "Column", "Category", "Role", "Detection Method",
            "Matched Values", "Confidence", "Evidence"
        ])

    sample_df = df.head(sample_size) if len(df) > sample_size else df

    for column in df.columns:
        column_name = str(column)
        col_category = classify_column(column_name)
        non_null_count = int(df[column].notna().sum())
        
        # 1. Column name check
        if col_category:
            role = CATEGORY_ROLE_MAP.get(col_category, "Quasi-Identifier")
            findings.append({
                "Column": column_name,
                "Category": col_category,
                "Role": role,
                "Detection Method": "Column name",
                "Matched Values": non_null_count,
                "Confidence": "High" if col_category in ["Email", "Phone Number", "Government ID"] else "Medium",
                "Evidence": f"Column name matches known keywords for '{col_category}'."
            })

        # 2. Pattern-based check on sampled string values
        clean_sample = sample_df[column].dropna().astype(str).str.strip()
        if len(clean_sample) == 0:
            continue

        for pat_name, pat_regex in PATTERNS.items():
            matches = clean_sample.apply(lambda val: bool(pat_regex.match(val)))
            match_count = int(matches.sum())
            ratio = match_count / len(clean_sample)

            if ratio >= 0.1:  # At least 10% match pattern
                estimated_total = int(ratio * non_null_count)
                role = CATEGORY_ROLE_MAP.get(pat_name, "Direct Identifier")
                
                # Check if already found under exact same category
                already = any(
                    f["Column"] == column_name and f["Category"] == pat_name 
                    for f in findings
                )
                if not already:
                    findings.append({
                        "Column": column_name,
                        "Category": pat_name,
                        "Role": role,
                        "Detection Method": "Value pattern",
                        "Matched Values": estimated_total,
                        "Confidence": "Very High" if ratio > 0.5 else "High",
                        "Evidence": f"{match_count}/{len(clean_sample)} sampled values ({ratio*100:.1f}%) matched {pat_name} format."
                    })

    return pd.DataFrame(
        findings,
        columns=[
            "Column",
            "Category",
            "Role",
            "Detection Method",
            "Matched Values",
            "Confidence",
            "Evidence",
        ]
    )
